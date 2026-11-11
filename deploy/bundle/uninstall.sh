#!/usr/bin/env bash
# Removes the OtterMSG node. Keeps /var/lib/otter and /var/backups/otter unless --purge. Run as root.
set -euo pipefail
say() { printf '==> %s\n' "$*"; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
purge=0; if [[ "${1:-}" == --purge ]]; then purge=1; fi
say "stopping services"
systemctl disable --now otter-node otter-backup.timer 2>/dev/null || true
rm -f /etc/systemd/system/otter-node.service /etc/systemd/system/otter-backup.service /etc/systemd/system/otter-backup.timer
systemctl daemon-reload
say "removing binary and configuration (keys are shredded)"
rm -f /usr/local/bin/otter-node /usr/local/bin/otter-node.prev /usr/local/bin/otter-node.failed /usr/local/bin/otter-node.new
for k in /etc/otter/node.key /etc/otter/tls.key; do
  if [[ -f $k ]]; then shred -u "$k"; fi
done
rm -rf /etc/otter /usr/local/lib/otter
if (( purge )); then
  say "purging data and backups"
  rm -rf /var/lib/otter /var/backups/otter
  userdel otter 2>/dev/null || true
else
  say "kept /var/lib/otter and /var/backups/otter (use --purge to delete)"
fi
