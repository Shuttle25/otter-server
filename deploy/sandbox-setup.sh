#!/usr/bin/env bash
# Installs the sandboxed otter-node / otter-backup units (D120) on a node that already runs otter-node, with rollback.
# Usage: sandbox-setup.sh LABEL [--if-older]
#   --if-older  exit 0 without a restart when both installed units already equal the templates (upgrade-all.sh)
# On the node: prints the exposure before, installs both units (previous ones kept as *.service.prev), daemon-reload,
# restarts otter-node and checks its health: service active + hello probe (health.sh), plus the "turn on" /
# "reality on" log lines when node.toml enables them. `otter-node status` is NOT used: a peer that is down (exit 2)
# says nothing about the sandbox. On failure the previous units come back and the node is restarted.
# Existing drop-ins (otter-node.service.d/netlink.conf, reality.conf) stay; they only repeat what the unit allows.
# Exit: 0 installed or already current, 2 rolled back, 3 manual action needed.
source "$(dirname "$0")/lib.sh"
usage="usage: sandbox-setup.sh LABEL [--if-older]"
label=${1:-}; [[ -n "$label" && "$label" != --* ]] || die "$usage"; shift
if_older=0
while (( $# )); do
  case "$1" in
    --if-older) if_older=1; shift ;;
    *) die "$usage" ;;
  esac
done
host_lookup "$label" || die "node $label has no SSH target: deploy/hosts.sh set $label root@HOST"
export SSH_PORT=$TARGET_PORT
tpl=$ROOT/deploy/templates
sum() { sha256sum < "$1" | cut -d' ' -f1; }

probe=$(remote "$TARGET" 'for u in otter-node otter-backup; do
    if [ -f /etc/systemd/system/$u.service ]; then sha256sum < /etc/systemd/system/$u.service | cut -d" " -f1; else echo none; fi
  done; if [ -x /usr/local/lib/otter/health.sh ]; then echo health; else echo no-health; fi') ||
  { say "cannot query $label ($TARGET)"; exit 3; }
cur_node="" cur_backup="" health=""
{ read -r cur_node || true; read -r cur_backup || true; read -r health || true; } <<< "$probe"
[[ "$health" == health ]] || die "$label has no /usr/local/lib/otter/health.sh (not installed by push.sh?)"
if (( if_older )) && [[ "$cur_node" == "$(sum "$tpl/otter-node.service")" && "$cur_backup" == "$(sum "$tpl/otter-backup.service")" ]]; then
  say "$label: sandbox units already current"; exit 0
fi

say "installing the sandboxed units on $label"
for u in otter-node otter-backup; do
  upload "$TARGET" "$tpl/$u.service" "/etc/systemd/system/$u.service.new" || { say "upload to $label failed; nothing changed"; exit 3; }
done
set +e
remote "$TARGET" bash -s <<'REMOTE'
set -uo pipefail
U=/etc/systemd/system
CFG=/etc/otter/node.toml
HEALTH=/usr/local/lib/otter/health.sh
say() { printf '==> %s\n' "$*"; }
score() { systemd-analyze security "$1.service" --no-pager 2>/dev/null | tail -n1 | sed 's/^→ *//'; }
turn_on() { awk '/^\[/{s=($0=="[turn]")} s && /^enabled *= *true/{f=1} END{exit !f}' "$CFG"; }
healthy() {
  "$HEALTH" || return 1
  if turn_on && ! journalctl -u otter-node --since "$since" --no-pager -o cat | grep -q '"msg":"turn on"'; then
    echo "TURN did not start under the new unit" >&2; return 1
  fi
  if grep -q '^\[reality\]' "$CFG" && ! journalctl -u otter-node --since "$since" --no-pager -o cat | grep -q '"reality on"'; then
    echo "REALITY did not start under the new unit" >&2; return 1
  fi
}
for u in otter-node otter-backup; do say "before: ${u}: $(score $u)"; done
mkdir -p /run/otter-sandbox
for u in otter-node otter-backup; do
  cp "$U/$u.service.new" "/run/otter-sandbox/$u.service"
  systemd-analyze verify "/run/otter-sandbox/$u.service" 2>&1 | grep -v 'is not executable' || true
done
rm -rf /run/otter-sandbox
for u in otter-node otter-backup; do
  if [[ -f $U/$u.service ]]; then cp -p "$U/$u.service" "$U/$u.service.prev"; else rm -f "$U/$u.service.prev"; fi
  chown root:root "$U/$u.service.new" && chmod 0644 "$U/$u.service.new" && mv "$U/$u.service.new" "$U/$u.service" || exit 3
done
since=$(date '+%Y-%m-%d %H:%M:%S')
if systemctl daemon-reload && systemctl restart otter-node && healthy; then
  for u in otter-node otter-backup; do say "after: ${u}: $(score $u)"; done
  exit 0
fi
say "health check failed under the sandbox: restoring the previous units"
for u in otter-node otter-backup; do
  if [[ -f $U/$u.service.prev ]]; then mv "$U/$u.service.prev" "$U/$u.service"; else rm -f "$U/$u.service"; fi
done
systemctl daemon-reload
systemctl restart otter-node
"$HEALTH" && exit 2
echo "ROLLBACK FAILED: see journalctl -u otter-node" >&2
exit 3
REMOTE
rc=$?
set -e
case $rc in
  0) say "$label: sandbox installed" ;;
  2) say "$label: sandbox rolled back, node runs its previous units (journalctl -u otter-node shows why)"; exit 2 ;;
  *) say "$label: check the server now (exit $rc)"; exit 3 ;;
esac
