#!/usr/bin/env bash
# Installs or updates this OtterMSG node from the bundle directory. Safe to run again. Run as root.
set -euo pipefail
cd "$(dirname "$0")"
say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"
command -v systemctl >/dev/null || die "systemd is required"
source /etc/os-release
[[ "$ID" == debian || "$ID" == ubuntu || "${ID_LIKE:-}" == *debian* ]] || die "Debian or Ubuntu required (found $ID)"
case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) die "unsupported architecture $(uname -m)" ;; esac
say "verifying SHA256SUMS"
sha256sum --quiet -c SHA256SUMS
source ./probe.env
if ss -ltnH "sport = :$OTTER_PORT" | grep -q . && ! systemctl is-active --quiet otter-node; then
  die "port $OTTER_PORT is in use: $(ss -ltnpH "sport = :$OTTER_PORT")"
fi

say "time synchronisation"
if ! systemctl is-active --quiet chrony 2>/dev/null; then
  if ! systemctl enable --now systemd-timesyncd 2>/dev/null; then
    apt-get update -q && apt-get install -y -q systemd-timesyncd && systemctl enable --now systemd-timesyncd
  fi
fi
for _ in $(seq 30); do [[ "$(timedatectl show -p NTPSynchronized --value)" == yes ]] && break; sleep 2; done
[[ "$(timedatectl show -p NTPSynchronized --value)" == yes ]] || say "WARNING: clock not synchronised yet (logins need ±5 min)"

if ! id otter >/dev/null 2>&1; then
  say "creating system user otter"
  useradd --system --home-dir /var/lib/otter --no-create-home --shell /usr/sbin/nologin otter
fi
if systemctl is-active --quiet otter-node; then say "stopping otter-node"; systemctl stop otter-node; fi

say "installing files"
install -d -o root -g otter -m 0750 /etc/otter
install -d -o otter -g otter -m 0700 /var/lib/otter
install -d -o otter -g otter -m 0700 /var/backups/otter
install -d -o root -g root -m 0755 /usr/local/lib/otter
install -o root -g otter -m 0640 node.key tls.key node.toml manifest.bin tls.crt probe.env /etc/otter/
# otter's data directory: root never writes inside it (D82). otter unpacks the decoy site itself, so a link
# planted there can only point otter at what otter may already write. (Comments here must not name the path:
# scripts_test.sh flags every root line that does.)
runuser -u otter -- mkdir -p -m 0755 /var/lib/otter/site
tar -C site -cf - . | runuser -u otter -- tar -C /var/lib/otter/site --no-same-owner --no-same-permissions --no-overwrite-dir -xf -
if [[ -x /usr/local/bin/otter-node ]] && ! cmp -s "otter-node-$arch" /usr/local/bin/otter-node; then
  cp -p /usr/local/bin/otter-node /usr/local/bin/otter-node.prev
fi
install -o root -g root -m 0755 "otter-node-$arch" /usr/local/bin/otter-node
install -o root -g root -m 0755 install.sh uninstall.sh backup.sh health.sh /usr/local/lib/otter/
install -o root -g root -m 0644 otter-node.service otter-backup.service otter-backup.timer /etc/systemd/system/

turn=0; if grep -q '^\[turn\]' /etc/otter/node.toml; then turn=1; fi
if (( turn )) && [[ ! -f /etc/otter/turn.secret ]]; then
  say "creating the TURN secret for calls (stays on this server, never printed)"
  /usr/local/bin/otter-node turn keygen --config /etc/otter/node.toml
  chown root:otter /etc/otter/turn.secret && chmod 0640 /etc/otter/turn.secret
fi

say "checking configuration"
runuser -u otter -- /usr/local/bin/otter-node check --config /etc/otter/node.toml
shopt -s nullglob
for f in invites/*.bin; do
  say "importing $(basename "$f")"
  # the bundle directory is root-only: root opens the file, otter reads it on stdin (D82)
  runuser -u otter -- /usr/local/bin/otter-node import --config /etc/otter/node.toml - < "$f"
done

if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  say "ufw: allowing SSH and $OTTER_PORT/tcp"
  ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp
  ufw allow "$OTTER_PORT/tcp"
  if (( turn )); then
    # TURN ports change the firewall: only on an explicit yes (push.sh asks on the admin's terminal), default No
    turn_ufw=${OTTER_TURN_UFW:-}
    if [[ -z "$turn_ufw" ]]; then
      turn_ufw=0
      if [[ -t 0 ]]; then
        read -r -p "Allow the TURN ports for calls in ufw (3478/udp 3478/tcp 5349/tcp 49160:49200/udp)? [y/N] " ans
        if [[ "$ans" =~ ^[yYдД] ]]; then turn_ufw=1; fi
      fi
    fi
    if [[ "$turn_ufw" == 1 ]]; then
      say "ufw: allowing the TURN ports for calls"
      for p in 3478/udp 3478/tcp 5349/tcp 49160:49200/udp; do echo "+ ufw allow $p"; ufw allow "$p"; done
    else
      say "ufw NOT changed for calls; to allow them run: ufw allow 3478/udp && ufw allow 3478/tcp && ufw allow 5349/tcp && ufw allow 49160:49200/udp"
    fi
  fi
else
  say "WARNING: no active host firewall. Allow only SSH and $OTTER_PORT/tcp in the provider's cloud firewall (docs/11 §8)."
fi
if (( turn )); then
  say "cloud firewall: also open UDP 3478, TCP 3478, TCP 5349, UDP 49160-49200 for calls (TURN relay)"
fi

say "starting otter-node"
systemctl daemon-reload
systemctl enable --quiet otter-node
systemctl restart otter-node
/usr/local/lib/otter/health.sh
say "node is up: $(/usr/local/bin/otter-node version), $OTTER_PROBE_URL"
say "single node? enable daily backups: /usr/local/lib/otter/backup.sh --install"
