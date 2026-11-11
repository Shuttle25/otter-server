#!/usr/bin/env bash
# Three local development nodes a, b, c (ports 8081-8083) replicating with each other. NOT for production.
#   scripts/dev-mesh.sh [--host H] [--reset [--yes]]   create (if missing) and start all three in the background
#   scripts/dev-mesh.sh stop                             stop all
#   scripts/dev-mesh.sh kill b | start b                 stop / start one node (failover testing)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dev="$root/.dev-mesh"
host="10.0.2.2"; host_set=0; reset=0; yes=0
labels=(a b c)
port_of() { case "$1" in a) echo 8081 ;; b) echo 8082 ;; c) echo 8083 ;; *) echo "unknown node $1" >&2; exit 2 ;; esac; }
export OTTER_ADMIN_PASSPHRASE="dev-only-passphrase"
node="$root/bin/otter-node"
admin="$root/bin/otter-admin --dir $dev/admin"

running() { [[ -f "$dev/$1.pid" ]] && kill -0 "$(cat "$dev/$1.pid")" 2>/dev/null; }
start_one() {
  if running "$1"; then echo "$1 already running (pid $(cat "$dev/$1.pid"))"; return; fi
  nohup "$node" run --config "$dev/$1.toml" >>"$dev/$1.log" 2>&1 &
  echo $! > "$dev/$1.pid"
  echo "$1 started on port $(port_of "$1") (pid $!, log $dev/$1.log)"
}
stop_one() {
  if running "$1"; then
    kill -INT "$(cat "$dev/$1.pid")"
    for _ in $(seq 50); do running "$1" || break; sleep 0.1; done
    echo "$1 stopped"
  fi
  rm -f "$dev/$1.pid"
}

case "${1:-}" in
  stop) for n in "${labels[@]}"; do stop_one "$n"; done; exit 0 ;;
  kill) stop_one "${2:?node label}"; exit 0 ;;
  start) make -C "$root" build >/dev/null; start_one "${2:?node label}"; exit 0 ;;
esac
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) ;;
    --reset) reset=1 ;;
    --yes) yes=1 ;;
    --host) host="$2"; host_set=1; shift ;;
    *) echo "usage: $0 [--host H] [--reset [--yes]] | stop | kill <n> | start <n>"; exit 2 ;;
  esac
  shift
done
make -C "$root" build >/dev/null

if [[ -d "$dev/admin" && $reset -eq 1 ]]; then
  echo "WARNING: --reset deletes the development mesh in $dev."
  echo "Apps that joined it will show 'no connection' and must be reinstalled (or have their data cleared) and join again."
  if [[ $yes -ne 1 ]]; then
    read -r -p "Create a new network? [y/N] " answer
    [[ "$answer" == "y" || "$answer" == "Y" ]] || { echo "Aborted."; exit 1; }
  fi
  for n in "${labels[@]}"; do stop_one "$n"; done
  rm -rf "$dev"
fi

if [[ ! -d "$dev/admin" ]]; then
  mkdir -p "$dev"
  $admin network init >/dev/null
  for n in "${labels[@]}"; do
    $admin node add --label "$n" --plain --wss-host "$host" --wss-port "$(port_of "$n")" >/dev/null
  done
  $admin manifest sign >/dev/null
  netpub="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["network_pub"])' "$dev/admin/network.json")"
  for n in "${labels[@]}"; do
    path="$(python3 -c 'import json,sys
for x in json.load(open(sys.argv[1]))["nodes"]:
    if x["label"] == sys.argv[2]: print(x["endpoints"][0]["path"])' "$dev/admin/nodes.json" "$n")"
    cat > "$dev/$n.toml" <<TOML
data_dir = "$dev/data-$n"
node_key = "$dev/admin/nodes/$n/node.key"
network_pub = "$netpub"
manifest_file = "$dev/admin/manifest.bin"
log_level = "debug"
[wss]
listen = "0.0.0.0:$(port_of "$n")"
path = "$path"
[mesh]
allow_plain = true
TOML
    $node import --config "$dev/$n.toml" "$dev/admin/manifest.bin" >/dev/null
  done
  out="$($admin invite bootstrap)"
  echo "$out"
  file="$(echo "$out" | sed -n 's/^Record: //p')"
  $node import --config "$dev/a.toml" "$file"   # replicates to b and c
  echo "$out" | grep '^otter://' > "$dev/bootstrap-invite.txt"
else
  current="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["nodes"][0]["endpoints"][0]["host"])' "$dev/admin/nodes.json")"
  echo "Reusing the development mesh in $dev (advertised host $current)."
  if [[ $host_set -eq 1 && "$host" != "$current" ]]; then
    echo "NOTE: --host $host differs from the existing mesh's host $current; use --reset to change it."
  fi
fi
for n in "${labels[@]}"; do start_one "$n"; done
echo "Bootstrap invite: $(cat "$dev/bootstrap-invite.txt")"
echo "Stop with: $0 stop"
