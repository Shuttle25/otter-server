#!/usr/bin/env bash
# One row per node: reachability, version, health, database counts (+ TURN allocations), disk, push, TURN relay
# (on/off; "-" = no [turn] in node.toml, e.g. nodes below 0.8.0); then each node's last 5
# connectivity log lines (otter-node netlog, 0.7.0+; older nodes print none). Usage: status.sh
source "$(dirname "$0")/lib.sh"
bad=0
netlogs=""
printf '%-12s %-22s %-10s %-6s %-8s %-48s %-6s %-6s %s\n' LABEL TARGET VERSION HELLO SERVICE STATS DISK PUSH TURN
for label in $(node_labels); do
  node_env "$label"
  host=$OTTER_HOST; if [[ "$host" == *:* ]]; then host="[$host]"; fi
  if "$NODE_BIN" probe --url "wss://$host:$OTTER_PORT$OTTER_PATH" --pin "$OTTER_PIN" \
       --expect-node "$OTTER_NODE_ID" --timeout 5s >/dev/null 2>&1; then hello=ok; else hello=FAIL; bad=1; fi
  target=- version=- service=- stats=- disk=- push=- turn=-
  if host_lookup "$label"; then
    target=$TARGET
    if out=$(SSH_PORT=$TARGET_PORT remote "$TARGET" \
        '/usr/local/bin/otter-node version; systemctl is-active otter-node || true;
         runuser -u otter -- /usr/local/bin/otter-node stats --config /etc/otter/node.toml 2>/dev/null || echo -;
         du -sh /var/lib/otter 2>/dev/null | cut -f1;
         journalctl -u otter-node -b --no-pager -o cat 2>/dev/null | grep -oE "\"msg\":\"push o(n|ff)" | tail -n1 |
           grep -q "on\$" && echo on || echo off;
         if grep -q "^\[turn\]" /etc/otter/node.toml 2>/dev/null; then
           journalctl -u otter-node -b --no-pager -o cat 2>/dev/null | grep -oE "\"msg\":\"turn o(n|ff)" | tail -n1 |
             grep -q "on\$" && echo on || echo off;
         else echo -; fi;
         echo --netlog--; runuser -u otter -- /usr/local/bin/otter-node netlog --config /etc/otter/node.toml --limit 5 2>/dev/null || true' 2>/dev/null); then
      version="" service="" stats="" disk="" push="" turn=""
      { read -r version || true; read -r service || true; read -r stats || true; read -r disk || true; read -r push || true
        read -r turn || true; } <<< "$out"
      [[ "$turn" != --netlog-- ]] || turn=""   # nodes answering without the TURN line
      nl=$(sed -n '/^--netlog--$/,$p' <<< "$out" | sed "1d; /^\$/d; s/^/  $label  /")
      [[ -z "$nl" ]] || netlogs+="$nl"$'\n'
      : "${version:=-}" "${service:=-}" "${stats:=-}" "${disk:=-}" "${push:=-}" "${turn:=-}"
      [[ "$service" == active ]] || bad=1
    else
      service=unreachable; bad=1
    fi
  fi
  printf '%-12s %-22s %-10s %-6s %-8s %-48s %-6s %-6s %s\n' "$label" "$target" "$version" "$hello" "$service" "$stats" "$disk" "$push" "$turn"
done
if [[ -n "$netlogs" ]]; then
  printf '\nconnectivity log (newest first):\n%s' "$netlogs"
fi
exit $bad
