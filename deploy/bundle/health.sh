#!/usr/bin/env bash
# Health check on the server: service active and the node answers its pinned hello on 127.0.0.1. Run as root.
set -euo pipefail
source /etc/otter/probe.env
for _ in $(seq 1 20); do
  if systemctl is-active --quiet otter-node &&
     /usr/local/bin/otter-node probe --url "$OTTER_PROBE_URL" --pin "$OTTER_PROBE_PIN" \
       --addr "127.0.0.1:$OTTER_PORT" --expect-node "$OTTER_NODE_ID" --timeout 3s; then
    exit 0
  fi
  sleep 1
done
echo "health check failed; last log lines:" >&2
journalctl -u otter-node -n 30 --no-pager >&2 || true
exit 1
