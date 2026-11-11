#!/usr/bin/env bash
# Daily node database backups (docs/11 §6). --install (root): enable the timer. --run (user otter, from the timer): one copy, keep 7.
set -euo pipefail
case "${1:-}" in
  --install)
    [[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
    systemctl daemon-reload
    systemctl enable --now otter-backup.timer
    echo "==> daily backups enabled into /var/backups/otter (7 kept): $(systemctl list-timers otter-backup.timer --no-pager | sed -n 2p)"
    ;;
  --run)
    out=/var/backups/otter/node-$(date +%F).db
    if [[ -e "$out" ]]; then echo "$out exists"; exit 0; fi
    /usr/local/bin/otter-node backup --config /etc/otter/node.toml --out "$out"
    ls -1t /var/backups/otter/node-*.db | tail -n +8 | xargs -r rm -f
    ;;
  *) echo "usage: backup.sh --install | --run" >&2; exit 2 ;;
esac
