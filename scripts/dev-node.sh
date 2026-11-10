#!/usr/bin/env bash
# Throwaway local network for development. NOT for production (plain ws://, passphrase in env).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dev="$root/.dev"
host="10.0.2.2"   # Android emulator's alias for the host machine
keep=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) keep=1 ;;
    --host) host="$2"; shift ;;
    *) echo "usage: $0 [--keep] [--host H]"; exit 2 ;;
  esac
  shift
done
export OTTER_ADMIN_PASSPHRASE="dev-only-passphrase"
make -C "$root" build >/dev/null
admin="$root/bin/otter-admin --dir $dev/admin"
node="$root/bin/otter-node"
if [[ $keep -eq 0 ]]; then
  rm -rf "$dev" && mkdir -p "$dev"
  $admin network init >/dev/null
  $admin node add --label dev --plain --wss-host "$host" --wss-port 8080 >/dev/null
  $admin manifest sign >/dev/null
  netpub="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["network_pub"])' "$dev/admin/network.json")"
  path="$(python3 - "$dev/admin/nodes.json" <<'EOF'
import json,sys
n=json.load(open(sys.argv[1]))["nodes"][0]
print(n["endpoints"][0]["path"])
EOF
)"
  cat > "$dev/node.toml" <<EOF
data_dir = "$dev/data"
node_key = "$dev/admin/nodes/dev/node.key"
network_pub = "$netpub"
manifest_file = "$dev/admin/manifest.bin"
log_level = "debug"
[wss]
listen = "0.0.0.0:8080"
path = "$path"
EOF
  $node import --config "$dev/node.toml" "$dev/admin/manifest.bin"
  out="$($admin invite bootstrap)"
  echo "$out"
  file="$(echo "$out" | sed -n 's/^Record: //p')"
  $node import --config "$dev/node.toml" "$file"
  echo "$out" | grep '^otter://' > "$dev/bootstrap-invite.txt"
fi
echo "Bootstrap invite: $(cat "$dev/bootstrap-invite.txt")"
exec $node run --config "$dev/node.toml"
