#!/usr/bin/env bash
# One row per node: reachability, version, health, database counts, disk. Usage: status.sh
source "$(dirname "$0")/lib.sh"
bad=0
printf '%-12s %-22s %-10s %-6s %-8s %-48s %s\n' LABEL TARGET VERSION HELLO SERVICE STATS DISK
for label in $(node_labels); do
  node_env "$label"
  host=$OTTER_HOST; if [[ "$host" == *:* ]]; then host="[$host]"; fi
  if "$NODE_BIN" probe --url "wss://$host:$OTTER_PORT$OTTER_PATH" --pin "$OTTER_PIN" \
       --expect-node "$OTTER_NODE_ID" --timeout 5s >/dev/null 2>&1; then hello=ok; else hello=FAIL; bad=1; fi
  target=- version=- service=- stats=- disk=-
  if host_lookup "$label"; then
    target=$TARGET
    if out=$(SSH_PORT=$TARGET_PORT remote "$TARGET" \
        '/usr/local/bin/otter-node version; systemctl is-active otter-node || true;
         runuser -u otter -- /usr/local/bin/otter-node stats --config /etc/otter/node.toml 2>/dev/null || echo -;
         du -sh /var/lib/otter 2>/dev/null | cut -f1' 2>/dev/null); then
      version="" service="" stats="" disk=""
      { read -r version || true; read -r service || true; read -r stats || true; read -r disk || true; } <<< "$out"
      : "${version:=-}" "${service:=-}" "${stats:=-}" "${disk:=-}"
      [[ "$service" == active ]] || bad=1
    else
      service=unreachable; bad=1
    fi
  fi
  printf '%-12s %-22s %-10s %-6s %-8s %-48s %s\n' "$label" "$target" "$version" "$hello" "$service" "$stats" "$disk"
done
exit $bad
