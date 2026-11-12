#!/usr/bin/env bash
# SSH targets of the nodes, kept in ~/.otter-admin/hosts as "label target [port]".
# Usage: hosts.sh set LABEL TARGET [SSH_PORT] | get LABEL | list | rm LABEL
source "$(dirname "$0")/lib.sh"
usage="usage: hosts.sh set LABEL TARGET [SSH_PORT] | get LABEL | list | rm LABEL"
cmd=${1:-}; shift || true
without() { if [[ -f "$HOSTS_FILE" ]]; then awk -v l="$1" '$1 != l' "$HOSTS_FILE"; fi; }
case "$cmd" in
set)
  label=${1:?$usage}; target=${2:?$usage}; port=${3:-}
  [[ "$label" =~ ^[a-z0-9-]+$ ]] || die "label must be lowercase letters, digits, -"
  [[ "$target" != *[[:space:]]* ]] || die "ssh target must not contain spaces"
  [[ -z "$port" || "$port" =~ ^[0-9]+$ ]] || die "ssh port must be a number"
  umask 077
  { without "$label"; echo "$label $target${port:+ $port}"; } > "$HOSTS_FILE.tmp"
  mv "$HOSTS_FILE.tmp" "$HOSTS_FILE"; chmod 0600 "$HOSTS_FILE"
  say "$label → $target${port:+ (port $port)}" ;;
get)
  label=${1:?$usage}
  host_lookup "$label" || exit 1
  echo "$TARGET $TARGET_PORT" ;;
list)
  for l in $(node_labels); do
    if host_lookup "$l"; then printf '%-12s %s %s\n' "$l" "$TARGET" "$TARGET_PORT"; else printf '%-12s -\n' "$l"; fi
  done ;;
rm)
  label=${1:?$usage}
  umask 077; without "$label" > "$HOSTS_FILE.tmp"; mv "$HOSTS_FILE.tmp" "$HOSTS_FILE" ;;
*) die "$usage" ;;
esac
