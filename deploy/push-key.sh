#!/usr/bin/env bash
# Installs the Firebase service-account key on one node and restarts it (D59). Usage: push-key.sh LABEL FCM.json
# The key goes only to /etc/otter/fcm.json on that node (0640 root:otter); nothing is copied or deleted locally.
source "$(dirname "$0")/lib.sh"
label=${1:?usage: push-key.sh LABEL /path/to/fcm.json}; key=${2:?usage: push-key.sh LABEL /path/to/fcm.json}
[[ -f "$key" ]] || die "no such file: $key"
grep -q '"type": *"service_account"' "$key" && grep -q '"project_id"' "$key" ||
  die "$key is not a Firebase service-account key (Firebase console → Project settings → Service accounts → Generate new private key)"
host_lookup "$label" || die "node $label has no SSH target: deploy/hosts.sh set $label root@HOST"
export SSH_PORT=$TARGET_PORT
say "uploading the push key to $TARGET:/etc/otter/fcm.json"
# through stdin with umask 077: the key is never readable by others, not even while in transit on the server
remote "$TARGET" 'umask 077 && cat > /etc/otter/fcm.json.new' < "$key"
remote "$TARGET" bash -s <<'REMOTE'
set -euo pipefail
install -o root -g otter -m 0640 /etc/otter/fcm.json.new /etc/otter/fcm.json
rm -f /etc/otter/fcm.json.new
# check the new config on a copy first: a pre-M5 otter-node rejects [push], and the live file must stay startable
cp -p /etc/otter/node.toml /etc/otter/node.toml.new
grep -q '^\[push\]' /etc/otter/node.toml.new || printf '\n[push]\nfcm_credentials = "/etc/otter/fcm.json"\n' >> /etc/otter/node.toml.new
if ! runuser -u otter -- /usr/local/bin/otter-node check --config /etc/otter/node.toml.new; then
  rm -f /etc/otter/node.toml.new
  echo "otter-node $(/usr/local/bin/otter-node version) does not accept the push config; node.toml left unchanged." >&2
  echo "Upgrade the node to an M5 release first (deploy/upgrade-all.sh VERSION), then re-run push-key.sh." >&2
  exit 1
fi
mv /etc/otter/node.toml.new /etc/otter/node.toml
since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart otter-node
/usr/local/lib/otter/health.sh
journalctl -u otter-node --since "$since" --no-pager -o cat | grep -m1 '"push on"' ||
  { echo "push did not start: see journalctl -u otter-node" >&2; exit 1; }
REMOTE
say "push key installed on $label. Next: otter-admin node set-push --label $label && otter-admin manifest sign && otter-admin manifest publish"
