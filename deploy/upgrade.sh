#!/usr/bin/env bash
# Upgrades otter-node on one server with automatic rollback (docs/11 §6).
# Usage: upgrade.sh <root@host> <otter-node binary for that server's arch>
# Exit: 0 upgraded, 2 rolled back, 3 rollback failed (manual action needed).
source "$(dirname "$0")/lib.sh"
target=${1:?usage: upgrade.sh <root@host> <binary>}; bin=${2:?usage: upgrade.sh <root@host> <binary>}
[[ -f "$bin" ]] || die "no such file: $bin"
sum=$(sha256sum "$bin" | cut -d' ' -f1)
say "uploading $(basename "$bin") to $target"
upload "$target" "$bin" /usr/local/bin/otter-node.new
set +e
remote "$target" bash -s -- "$sum" <<'REMOTE'
set -euo pipefail
# root's ssh session starts in /root, which otter cannot enter; `find` run as otter must return to its start dir
cd /
sum=$1
say() { printf '==> %s\n' "$*"; }
echo "$sum  /usr/local/bin/otter-node.new" | sha256sum --quiet -c
chmod 0755 /usr/local/bin/otter-node.new
ts=$(date +%Y%m%d-%H%M%S)
install -d -o otter -g otter -m 0700 /var/backups/otter
backup=/var/backups/otter/pre-upgrade-$ts.db
say "backing up the database to $backup (installed binary: $(/usr/local/bin/otter-node version))"
runuser -u otter -- /usr/local/bin/otter-node backup --config /etc/otter/node.toml --out "$backup"
# C26 (D84): copies made before 0.8.3 are 0644; keep the newest 3 pre-upgrade copies. All as otter (D82).
runuser -u otter -- find /var/backups/otter -maxdepth 1 -type f -name '*.db' -exec chmod 0600 {} +
runuser -u otter -- find /var/backups/otter -maxdepth 1 -type f -name 'pre-upgrade-*.db' -print0 | sort -zr | tail -zn +4 | runuser -u otter -- xargs -0r rm -f --
say "swapping binaries"
systemctl stop otter-node
cp -p /usr/local/bin/otter-node /usr/local/bin/otter-node.prev
cp -p /etc/otter/node.toml /etc/otter/node.toml.prev
mv /usr/local/bin/otter-node.new /usr/local/bin/otter-node
systemctl start otter-node || true
if /usr/local/lib/otter/health.sh; then
  say "upgraded to $(/usr/local/bin/otter-node version)"
  exit 0
fi
say "health check failed: rolling back"
systemctl stop otter-node || true
mv /usr/local/bin/otter-node /usr/local/bin/otter-node.failed
cp -p /usr/local/bin/otter-node.prev /usr/local/bin/otter-node
cp -p /etc/otter/node.toml.prev /etc/otter/node.toml
runuser -u otter -- rm -f /var/lib/otter/node.db-wal /var/lib/otter/node.db-shm
# as otter: the backup sits in otter's directory and could be a planted link (D82)
runuser -u otter -- install -m 0600 "$backup" /var/lib/otter/node.db
systemctl start otter-node || true
if /usr/local/lib/otter/health.sh; then
  say "rolled back to $(/usr/local/bin/otter-node version); the failed binary is /usr/local/bin/otter-node.failed"
  exit 2
fi
echo "ROLLBACK FAILED: see journalctl -u otter-node" >&2
exit 3
REMOTE
rc=$?
set -e
case $rc in
  0) say "upgrade of $target done" ;;
  2) printf 'error: upgrade failed and was rolled back on %s\n' "$target" >&2; exit 2 ;;
  *) printf 'error: upgrade of %s failed (exit %s) — check the server now\n' "$target" "$rc" >&2; exit 3 ;;
esac
