#!/usr/bin/env bash
# Health checks for one node (docs/11 §7). Usage: check.sh <label> [ssh-target]
source "$(dirname "$0")/lib.sh"
label=${1:?usage: check.sh <label> [ssh-target]}; target=${2:-}
node_env "$label"
host=$OTTER_HOST; if [[ "$host" == *:* ]]; then host="[$host]"; fi
url="wss://$host:$OTTER_PORT$OTTER_PATH"
addr_args=(); curl_args=()
if [[ -n "${OTTER_PROBE_ADDR:-}" ]]; then
  addr_args=(--addr "$OTTER_PROBE_ADDR")
  curl_args=(--connect-to "$OTTER_HOST:$OTTER_PORT:${OTTER_PROBE_ADDR%:*}:${OTTER_PROBE_ADDR##*:}")
fi
fails=0
row() { printf '%-28s %s\n' "$1" "$2"; if [[ "$2" != PASS* && "$2" != SKIP* ]]; then fails=$((fails + 1)); fi; }

if [[ "${OTTER_SKIP_DNS:-0}" == 1 ]]; then row "DNS" "SKIP (OTTER_SKIP_DNS)"
elif dns=$(admin dns check --label "$label" 2>&1); then row "DNS" "PASS ($(tail -n1 <<< "$dns" | tr -s ' '))"
else row "DNS" "FAIL ($(tail -n1 <<< "$dns"))"; fi

if out=$("$NODE_BIN" probe --url "$url" --pin "$OTTER_PIN" --expect-node "$OTTER_NODE_ID" "${addr_args[@]}" 2>&1); then
  row "pinned hello" "PASS ($out)"; else row "pinned hello" "FAIL ($out)"; fi
random_pin=$(head -c 32 /dev/urandom | base64)
if "$NODE_BIN" probe --url "$url" --pin "$random_pin" "${addr_args[@]}" >/dev/null 2>&1; then
  row "wrong pin rejected" "FAIL (accepted)"; else row "wrong pin rejected" "PASS"; fi
code=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' "${curl_args[@]}" "https://$host:$OTTER_PORT/" || true)
if [[ "$code" == 200 ]]; then row "decoy site" "PASS"; else row "decoy site" "FAIL (HTTP $code)"; fi

if [[ -n "$target" ]]; then
  st=$(remote "$target" systemctl is-active otter-node || true)
  if [[ "$st" == active ]]; then row "service" "PASS"; else row "service" "FAIL ($st)"; fi
  ntp=$(remote "$target" timedatectl show -p NTPSynchronized --value || true)
  if [[ "$ntp" == yes ]]; then row "clock synchronised" "PASS"; else row "clock synchronised" "FAIL ($ntp)"; fi
  if remote "$target" /usr/local/lib/otter/health.sh >/dev/null 2>&1; then row "server-side health" "PASS"; else row "server-side health" "FAIL"; fi
  n=$(remote "$target" "journalctl -u otter-node -b --no-pager | grep -c 'not listed in the manifest' || true")
  if [[ "$n" == 0 ]]; then row "listed in manifest" "PASS"; else row "listed in manifest" "FAIL ($n warnings)"; fi
fi
(( fails == 0 )) || die "$fails check(s) failed"
say "all checks passed for $label"
