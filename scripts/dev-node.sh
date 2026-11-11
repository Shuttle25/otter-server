#!/usr/bin/env bash
# One local development node. NOT for production (plain ws://, passphrase in env).
# An existing .dev/ network is reused; --reset creates a new one (installed apps must then re-join).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dev="$root/.dev"
host="10.0.2.2"   # Android emulator's alias for the host machine
host_set=0; reset=0; yes=0
usage() { echo "usage: $0 [--host H] [--reset [--yes]]   (--keep is accepted and ignored: reuse is the default)"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) ;;
    --reset) reset=1 ;;
    --yes) yes=1 ;;
    --host) host="$2"; host_set=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done
export OTTER_ADMIN_PASSPHRASE="dev-only-passphrase"
make -C "$root" build >/dev/null
admin="$root/bin/otter-admin --dir $dev/admin"
node="$root/bin/otter-node"

if [[ -f "$dev/node.toml" && $reset -eq 1 ]]; then
  echo "WARNING: --reset deletes the development network in $dev."
  echo "Apps that joined it will show 'no connection' and must be reinstalled (or have their data cleared) and join again."
  if [[ $yes -ne 1 ]]; then
    read -r -p "Create a new network? [y/N] " answer
    [[ "$answer" == "y" || "$answer" == "Y" ]] || { echo "Aborted."; exit 1; }
  fi
  rm -rf "$dev"
fi

if [[ ! -f "$dev/node.toml" ]]; then
  mkdir -p "$dev"
  $admin network init >/dev/null
  $admin node add --label dev --plain --wss-host "$host" --wss-port 8080 >/dev/null
  $admin manifest sign >/dev/null
  netpub="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["network_pub"])' "$dev/admin/network.json")"
  path="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["nodes"][0]["endpoints"][0]["path"])' "$dev/admin/nodes.json")"
  cat > "$dev/node.toml" <<TOML
data_dir = "$dev/data"
node_key = "$dev/admin/nodes/dev/node.key"
network_pub = "$netpub"
manifest_file = "$dev/admin/manifest.bin"
log_level = "debug"
[wss]
listen = "0.0.0.0:8080"
path = "$path"
TOML
  $node import --config "$dev/node.toml" "$dev/admin/manifest.bin"
  out="$($admin invite bootstrap)"
  echo "$out"
  file="$(echo "$out" | sed -n 's/^Record: //p')"
  $node import --config "$dev/node.toml" "$file"
  echo "$out" | grep '^otter://' > "$dev/bootstrap-invite.txt"
else
  current="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["nodes"][0]["endpoints"][0]["host"])' "$dev/admin/nodes.json")"
  echo "Reusing the development network in $dev (advertised host $current)."
  if [[ $host_set -eq 1 && "$host" != "$current" ]]; then
    echo "NOTE: --host $host differs from the existing network's host $current; use --reset to change it."
  fi
fi
echo "Bootstrap invite: $(cat "$dev/bootstrap-invite.txt")"
exec $node run --config "$dev/node.toml"
