#!/usr/bin/env bash
# Turns on the REALITY listener on one node (D72) and adds its endpoint to the admin state.
# Usage: reality-setup.sh LABEL --dest HOST [--port 443] [--force]
# The private key is generated on the node and never leaves it. The live node.toml is changed only after the new
# config passed `otter-node check`; if REALITY does not come up, the node goes back to its previous config.
source "$(dirname "$0")/lib.sh"
usage="usage: reality-setup.sh LABEL --dest HOST [--port 443] [--force]"
label=${1:-}; [[ -n "$label" && "$label" != --* ]] || die "$usage"; shift
dest=""; port=443; force=0
while (( $# )); do
  case "$1" in
    --dest) dest=${2:?$usage}; shift 2 ;;
    --port) port=${2:?$usage}; shift 2 ;;
    --force) force=1; shift ;;
    *) die "$usage" ;;
  esac
done
[[ -n "$dest" ]] || die "$usage"
[[ "$dest" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "--dest must be a host name, e.g. www.microsoft.com"
[[ "$port" =~ ^[0-9]+$ ]] && (( port > 0 && port < 65536 )) || die "--port must be 1–65535"
host_lookup "$label" || die "node $label has no SSH target: deploy/hosts.sh set $label root@HOST"
export SSH_PORT=$TARGET_PORT
ip=$(admin_node_ip "$label")
[[ -n "$ip" ]] || die "no IP recorded for $label (otter-admin node set-ip --label $label --ip IP)"
say "checking the camouflage site $dest from $label"
remote "$TARGET" "/usr/local/bin/otter-node reality-check $dest" ||
  die "$dest failed the check on $label; pick another (e.g. www.microsoft.com, dl.google.com)"
sid=$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')
vless=$(cat /proc/sys/kernel/random/uuid)
say "configuring REALITY on $label (:$port, camouflage $dest)"
pub=$(remote "$TARGET" bash -s -- "$dest" "$port" "$sid" "$vless" "$force" <<'REMOTE'
set -euo pipefail
dest=$1 port=$2 sid=$3 vless=$4 force=$5
if grep -q '^\[reality\]' /etc/otter/node.toml && [[ $force != 1 ]]; then
  echo "node.toml already has [reality]; re-run with --force to replace it" >&2; exit 1
fi
trap 'rm -f /etc/otter/node.toml.new /etc/otter/node.toml.tmp' EXIT
cp -p /etc/otter/node.toml /etc/otter/node.toml.new
# drop an old [reality] section (to the next section or EOF)
awk 'BEGIN{s=0} /^\[reality\]/{s=1;next} /^\[/{s=0} !s' /etc/otter/node.toml.new > /etc/otter/node.toml.tmp
mv /etc/otter/node.toml.tmp /etc/otter/node.toml.new
cat >> /etc/otter/node.toml.new <<EOF

# VLESS+REALITY listener for peers (D72), written by deploy/reality-setup.sh
[reality]
listen = ":$port"
private_key_file = "/etc/otter/reality.key"
dest = "$dest:443"
server_names = ["$dest"]
short_ids = ["$sid"]
vless_uuid = "$vless"
EOF
chown root:otter /etc/otter/node.toml.new; chmod 0640 /etc/otter/node.toml.new
if ! out=$(/usr/local/bin/otter-node reality keygen --config /etc/otter/node.toml.new); then
  echo "otter-node $(/usr/local/bin/otter-node version) cannot generate a REALITY key; upgrade to 0.7.0+ first" >&2; exit 1
fi
chown root:otter /etc/otter/reality.key; chmod 0640 /etc/otter/reality.key
if ! runuser -u otter -- /usr/local/bin/otter-node check --config /etc/otter/node.toml.new >&2; then
  echo "otter-node $(/usr/local/bin/otter-node version) rejects the REALITY config; upgrade to 0.7.0+ first" >&2; exit 1
fi
mkdir -p /etc/systemd/system/otter-node.service.d
printf '[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n' \
  > /etc/systemd/system/otter-node.service.d/reality.conf
systemctl daemon-reload
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  ufw allow "$port/tcp" >&2
fi
cp -p /etc/otter/node.toml /etc/otter/node.toml.pre-reality
mv /etc/otter/node.toml.new /etc/otter/node.toml
since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart otter-node
if ! /usr/local/lib/otter/health.sh >&2 ||
   ! journalctl -u otter-node --since "$since" --no-pager -o cat | grep '"reality on"' >/dev/null; then
  echo "REALITY did not start; restoring the previous config" >&2
  mv /etc/otter/node.toml.pre-reality /etc/otter/node.toml
  systemctl restart otter-node; /usr/local/lib/otter/health.sh >&2 || true
  exit 1
fi
echo "${out##*: }"
REMOTE
) || die "REALITY setup failed on $label (node left on its previous config)"
[[ -n "$pub" ]] || die "no public key from $label"
say "adding the REALITY endpoint ($ip:$port) to the admin state"
admin node add-reality --label "$label" --host "$ip" --port "$port" --pub "$pub" --server-name "$dest" --short-id "$sid" --uuid "$vless"
say "REALITY is on for $label. Next (your terminal): otter-admin manifest sign && otter-admin manifest publish"
say "and allow $port/tcp in the provider's cloud firewall if it has one"
