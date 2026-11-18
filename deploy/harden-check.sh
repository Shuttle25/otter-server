#!/usr/bin/env bash
# Read-only hardening report for every node (or the labels given): SSH, security updates, pending reboot, firewall,
# public listeners that are not otter-node's or sshd's, metrics on loopback, unit sandbox scores, the otter user,
# binary and key-file ownership, NTP (D120). One SSH call per node streams deploy/bundle/harden-report.sh (the repo
# copy, so older nodes get the current checks). Changes nothing on the servers; fix findings by hand, each one
# asked first. Exit 1 on any FAIL line or unreachable node. Usage: harden-check.sh [LABEL...]
source "$(dirname "$0")/lib.sh"
labels=("$@")
(( ${#labels[@]} )) || mapfile -t labels < <(node_labels)
bad=0
for label in "${labels[@]}"; do
  printf '\n== %s\n' "$label"
  if ! host_lookup "$label"; then echo "  no SSH target: deploy/hosts.sh set $label root@HOST"; bad=1; continue; fi
  if ! out=$(SSH_PORT=$TARGET_PORT remote "$TARGET" 'bash -s' < "$ROOT/deploy/bundle/harden-report.sh" 2>&1); then
    echo "  unreachable: $out"; bad=1; continue
  fi
  sed 's/^/  /' <<< "$out"
  if grep -q '^FAIL ' <<< "$out"; then bad=1; fi
done
if (( bad == 0 )); then printf '\nno FAIL; review the WARN lines\n'
else printf '\nFAIL lines or unreachable nodes need attention (fix by hand, each step asked first)\n'; fi
exit $bad
