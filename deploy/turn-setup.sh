#!/usr/bin/env bash
# Turns on the embedded TURN relay for calls (M8, D77) on a node that already runs otter-node 0.8.0+.
# Usage: turn-setup.sh LABEL [--if-missing] [--force]
#   --if-missing  exit 0 when node.toml already has [turn] (upgrade-all.sh uses this)
#   --force       replace an existing [turn] section (the secret file is kept)
# The secret is generated on the node (/etc/otter/turn.secret) and never printed or copied. The live node.toml is
# changed only after the new config passed `otter-node check`; if TURN does not come up, the node goes back to its
# previous config (node.toml.pre-turn). ufw is changed only on an explicit yes on a terminal (default No).
source "$(dirname "$0")/lib.sh"
usage="usage: turn-setup.sh LABEL [--if-missing] [--force]"
label=${1:-}; [[ -n "$label" && "$label" != --* ]] || die "$usage"; shift
if_missing=0; force=0
while (( $# )); do
  case "$1" in
    --if-missing) if_missing=1; shift ;;
    --force) force=1; shift ;;
    *) die "$usage" ;;
  esac
done
host_lookup "$label" || die "node $label has no SSH target: deploy/hosts.sh set $label root@HOST"
export SSH_PORT=$TARGET_PORT
ip=$(admin_node_ip "$label")
[[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] ||
  die "no IPv4 address recorded for $label (TURN relay_ip): otter-admin node set-ip --label $label --ip IP"

probe=$(remote "$TARGET" '/usr/local/bin/otter-node version;
  if grep -q "^\[turn\]" /etc/otter/node.toml; then echo turn; else echo no-turn; fi;
  if command -v ufw >/dev/null && ufw status | grep -q "^Status: active"; then echo ufw; else echo no-ufw; fi') ||
  die "cannot query $label ($TARGET)"
ver="" has_turn="" fw=""
{ read -r ver || true; read -r has_turn || true; read -r fw || true; } <<< "$probe"
version_ge "$ver" 0.8.0 || die "$label runs otter-node ${ver:-?}; TURN needs 0.8.0+ (deploy/upgrade-all.sh 0.8.0 --only $label)"
if [[ "$has_turn" == turn ]]; then
  if (( if_missing )); then say "$label: node.toml already has [turn]; left as it is"; exit 0; fi
  (( force )) || die "$label: node.toml already has [turn]; re-run with --force to replace it"
fi

ufw_cmds=""; for p in $TURN_PORTS; do ufw_cmds+="${ufw_cmds:+ && }ufw allow $p"; done
ufw=0
if [[ "$fw" == ufw ]]; then
  if [[ -t 0 ]]; then
    read -r -p "ufw is active on $label. Allow the TURN ports for calls ($TURN_PORTS) after TURN is up? [y/N] " ans
    if [[ "$ans" =~ ^[yYдД] ]]; then ufw=1; fi
  fi
  (( ufw )) || say "ufw on $label will NOT be changed; calls through it need (on the node): $ufw_cmds"
fi

say "configuring TURN on $label (relay_ip $ip)"
remote "$TARGET" bash -s -- "$ip" "$force" "$if_missing" "$ufw" <<'REMOTE' || die "TURN setup failed on $label (node left on its previous config)"
set -euo pipefail
relay_ip=$1 force=$2 if_missing=$3 ufw=$4
cfg=/etc/otter/node.toml
if grep -q '^\[turn\]' "$cfg"; then
  if [[ $if_missing == 1 ]]; then echo "node.toml already has [turn]; left as it is"; exit 0; fi
  if [[ $force != 1 ]]; then echo "node.toml already has [turn]; re-run with --force to replace it" >&2; exit 1; fi
fi
trap 'rm -f /etc/otter/node.toml.new /etc/otter/node.toml.tmp' EXIT
cp -p "$cfg" /etc/otter/node.toml.new
# drop an old [turn] section (to the next section or EOF) and its comment lines
awk 'BEGIN{s=0} /^# Embedded TURN relay/||/^# Ports: UDP 3478/{next} /^\[turn\]/{s=1;next} /^\[/{s=0} !s' \
  /etc/otter/node.toml.new > /etc/otter/node.toml.tmp
mv /etc/otter/node.toml.tmp /etc/otter/node.toml.new
cat >> /etc/otter/node.toml.new <<EOF

# Embedded TURN relay for calls (M8, D77), written by deploy/turn-setup.sh.
# Ports: UDP 3478, TCP 3478, TLS 5349, UDP relay 49160-49200. Secret: /etc/otter/turn.secret.
[turn]
enabled = true
relay_ip = "$relay_ip"
EOF
chown root:otter /etc/otter/node.toml.new; chmod 0640 /etc/otter/node.toml.new
if [[ ! -f /etc/otter/turn.secret ]]; then
  echo "creating the TURN secret (stays on this server, never printed)" >&2
  if ! /usr/local/bin/otter-node turn keygen --config /etc/otter/node.toml.new >&2; then
    echo "otter-node $(/usr/local/bin/otter-node version) cannot generate a TURN secret; upgrade to 0.8.0+ first" >&2; exit 1
  fi
  chown root:otter /etc/otter/turn.secret; chmod 0640 /etc/otter/turn.secret
fi
if ! runuser -u otter -- /usr/local/bin/otter-node check --config /etc/otter/node.toml.new >&2; then
  echo "otter-node $(/usr/local/bin/otter-node version) rejects the TURN config; node.toml not changed" >&2; exit 1
fi
# The relay lists network interfaces (netlink). Units installed before 0.8.0 allow only AF_INET/AF_INET6/AF_UNIX;
# a drop-in adds AF_NETLINK (RestrictAddressFamilies lines are merged, so the rest of the hardening stays).
unit=/etc/systemd/system/otter-node.service
dropin=/etc/systemd/system/otter-node.service.d/netlink.conf
if ! grep -q '^RestrictAddressFamilies=.*AF_NETLINK' "$unit" && [[ ! -f $dropin ]]; then
  echo "allowing AF_NETLINK for otter-node (systemd drop-in $dropin)" >&2
  mkdir -p "$(dirname "$dropin")"
  printf '[Service]\n# M8 TURN relay: interface listing needs netlink (added by deploy/turn-setup.sh)\nRestrictAddressFamilies=AF_NETLINK\n' > "$dropin"
  systemctl daemon-reload
fi
cp -p "$cfg" /etc/otter/node.toml.pre-turn
mv /etc/otter/node.toml.new "$cfg"
since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart otter-node
if ! /usr/local/lib/otter/health.sh >&2 ||
   ! journalctl -u otter-node --since "$since" --no-pager -o cat | grep '"msg":"turn on"' >/dev/null; then
  echo "TURN did not start; restoring the previous config (node.toml.pre-turn)" >&2
  mv /etc/otter/node.toml.pre-turn "$cfg"
  systemctl restart otter-node; /usr/local/lib/otter/health.sh >&2 || true
  exit 1
fi
echo "TURN is on"
if [[ $ufw == 1 ]] && command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  for p in 3478/udp 3478/tcp 5349/tcp 49160:49200/udp; do echo "+ ufw allow $p"; ufw allow "$p"; done
fi
REMOTE
say "TURN is on for $label. If its provider has a cloud firewall, open there: UDP 3478, TCP 3478, TCP 5349, UDP 49160-49200"
