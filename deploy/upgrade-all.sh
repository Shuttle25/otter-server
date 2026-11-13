#!/usr/bin/env bash
# Rolling upgrade of every node (or --only LABEL...) to VERSION; stops at the first failure.
# For VERSION 0.8.0+ each node then gets the TURN relay for calls (turn-setup.sh --if-missing), unless --no-turn.
# Then offers the news dialog (news-dialog.sh) when run from a terminal, unless --no-news.
# Usage: upgrade-all.sh VERSION [--only LABEL]... [--no-news] [--no-turn]
# Exit: 0 all done, 2 rolled back, 3 manual action needed.
source "$(dirname "$0")/lib.sh"
usage="usage: upgrade-all.sh VERSION [--only LABEL]... [--no-news] [--no-turn]"
version=${1:?$usage}; shift
only=() news=1 no_turn=0
while (( $# )); do case "$1" in
  --only) only+=("${2:?$usage}"); shift 2 ;;
  --no-news) news=0; shift ;;
  --no-turn) no_turn=1; shift ;;
  *) die "$usage" ;;
esac; done
all=$(node_labels)
for o in "${only[@]}"; do grep -qx -- "$o" <<< "$all" || die "unknown node $o"; done
labels=()
for l in $all; do
  if (( ${#only[@]} == 0 )) || printf '%s\n' "${only[@]}" | grep -qx -- "$l"; then labels+=("$l"); fi
done
(( ${#labels[@]} )) || die "no matching nodes"
for l in "${labels[@]}"; do host_lookup "$l" || die "node $l has no SSH target: deploy/hosts.sh set $l root@HOST"; done

if [[ ! -f "$ROOT/dist/otter-node_${version}_linux_amd64" || ! -f "$ROOT/dist/otter-node_${version}_linux_arm64" ]]; then
  say "building release $version"
  make -C "$ROOT" -s release VERSION="$version"
fi

declare -A result
for l in "${labels[@]}"; do result[$l]="not attempted"; done
summary() { for l in "${labels[@]}"; do printf '%-12s %s\n' "$l" "${result[$l]}"; done; }
# turn_on LABEL: after the node runs VERSION (0.8.0+), [turn] is written only now (older binaries refuse it)
turn_on() {
  (( no_turn == 0 )) && version_ge "$version" 0.8.0 || return 0
  if "$ROOT/deploy/turn-setup.sh" "$1" --if-missing; then
    result[$1]+=", TURN ok"
  else
    say "WARNING: $1: TURN not enabled (see above); calls cannot use this node's relay. Retry: deploy/turn-setup.sh $1"
    result[$1]+=", TURN NOT ENABLED"
  fi
}
for l in "${labels[@]}"; do
  host_lookup "$l"
  export OTTER_SSH_PORT=$TARGET_PORT SSH_PORT=$TARGET_PORT
  m=$(remote "$TARGET" uname -m) || { result[$l]="unreachable"; summary; exit 3; }
  case "$m" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die "node $l: unsupported CPU type $m" ;; esac
  cur=$(remote "$TARGET" /usr/local/bin/otter-node version 2>/dev/null || echo unknown)
  if [[ "$cur" == "$version" ]]; then result[$l]="already $version"; turn_on "$l"; continue; fi
  say "upgrading $l ($TARGET, $arch) from $cur to $version"
  set +e; "$ROOT/deploy/upgrade.sh" "$TARGET" "$ROOT/dist/otter-node_${version}_linux_$arch"; rc=$?; set -e
  case $rc in
    0) result[$l]="upgraded $cur → $version"; turn_on "$l" ;;
    2) result[$l]="ROLLED BACK (still $cur)"; summary; exit 2 ;;
    *) result[$l]="FAILED — check the server now"; summary; exit 3 ;;
  esac
done
summary
say "all selected nodes are on $version"
if (( news )) && [[ -t 0 ]]; then
  "$ROOT/deploy/news-dialog.sh" "$version" || say "news not sent; retry: deploy/news-dialog.sh $version"
fi
