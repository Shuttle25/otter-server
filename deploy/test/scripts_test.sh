#!/usr/bin/env bash
# Offline tests for the admin-side deploy scripts (no VM; ssh/scp are stubs).
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d); trap 'rm -rf "$work"; rm -f dist/otter-node_0.0.0-st_linux_* dist/bundle-n3.*' EXIT
fail() { echo "scripts test: FAIL: $*" >&2; exit 1; }
export OTTER_ADMIN_DIR="$work/admin" OTTER_ADMIN_PASSPHRASE=scripts-test-passphrase
unset OTTER_SSH_PORT OTTER_SSH_OPTS
make -s build; mkdir -p dist
bin/otter-admin --dir "$OTTER_ADMIN_DIR" network init >/dev/null
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node add --label n1 --wss-host 192.0.2.1 --ip 192.0.2.1 >/dev/null
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node add --label n2 --wss-host 192.0.2.2 --ip 192.0.2.2 >/dev/null
bin/otter-admin --dir "$OTTER_ADMIN_DIR" manifest sign >/dev/null

# --- hosts.sh
deploy/hosts.sh set n1 root@n1.example
[[ "$(deploy/hosts.sh get n1)" == "root@n1.example 22" ]] || fail "get n1"
deploy/hosts.sh set n1 root@other 2222
[[ "$(deploy/hosts.sh get n1)" == "root@other 2222" ]] || fail "replace n1"
[[ "$(grep -c '^n1 ' "$OTTER_ADMIN_DIR/hosts")" == 1 ]] || fail "duplicate line"
[[ "$(stat -c %a "$OTTER_ADMIN_DIR/hosts")" == 600 ]] || fail "hosts mode"
if deploy/hosts.sh get n2 >/dev/null 2>&1; then fail "unknown label found"; fi
list=$(deploy/hosts.sh list)
grep -q '^n1 *root@other *2222$' <<< "$list" || fail "list n1: $list"
grep -q '^n2 *-$' <<< "$list" || fail "list n2: $list"
if deploy/hosts.sh set 'Bad Label' root@x 2>/dev/null; then fail "bad label accepted"; fi
if deploy/hosts.sh set n2 root@x port 2>/dev/null; then fail "bad port accepted"; fi
deploy/hosts.sh rm n1
if deploy/hosts.sh get n1 >/dev/null 2>&1; then fail "rm"; fi

echo "scripts test: ok"
