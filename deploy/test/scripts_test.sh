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

# --- add-node.sh argument checks (no network access needed: they fail before any ssh)
if out=$(deploy/add-node.sh n3 root@n3 2>&1); then fail "add-node without --ip"; fi
grep -q -- '--ip' <<< "$out" || fail "add-node usage: $out"
deploy/hosts.sh set n2 root@n2.example
if out=$(deploy/add-node.sh n2 root@elsewhere --ip 192.0.2.2 2>&1); then fail "add-node to another target"; fi
grep -q 'already registered' <<< "$out" || fail "add-node conflict message: $out"
# resume: a node added but never signed gets signed on the re-run; it stops at the missing release (before ssh)
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node add --label n3 --wss-host 192.0.2.3 --ip 192.0.2.3 >/dev/null
if out=$(deploy/add-node.sh n3 root@n3.example --ip 192.0.2.3 --version 0.0.0-missing 2>&1); then fail "add-node without release"; fi
grep -q 'skipping node add' <<< "$out" || fail "add-node resume: $out"
grep -q 're-run the same command' <<< "$out" || fail "add-node resume hint: $out"
bin/otter-admin --dir "$OTTER_ADMIN_DIR" manifest show | grep -q '"n3"' || fail "n3 not signed into the manifest"
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node remove --label n3 >/dev/null
bin/otter-admin --dir "$OTTER_ADMIN_DIR" manifest sign >/dev/null
deploy/hosts.sh rm n3

# --- status.sh with stubbed ssh: unreachable nodes are reported, exit 1
mkdir -p "$work/stub"
printf '#!/bin/sh\necho "ssh: connect to host: Connection refused" >&2\nexit 255\n' > "$work/stub/ssh"
chmod +x "$work/stub/ssh"
if out=$(PATH="$work/stub:$PATH" deploy/status.sh 2>&1); then fail "status should fail"; fi
grep -q '^n1 ' <<< "$out" && grep -q '^n2 ' <<< "$out" || fail "status rows: $out"

# --- upgrade-all.sh: refuses when a node has no host, before touching anything
deploy/hosts.sh rm n2
touch dist/otter-node_0.0.0-st_linux_amd64 dist/otter-node_0.0.0-st_linux_arm64
if out=$(deploy/upgrade-all.sh 0.0.0-st 2>&1); then fail "upgrade-all without hosts"; fi
grep -q 'hosts.sh set n1' <<< "$out" || fail "upgrade-all message: $out"
# --only limits the set; an unknown CPU type is refused
deploy/hosts.sh set n1 root@n1.example
printf '#!/bin/sh\ncase "$*" in *uname*) echo sparc64;; *) exit 0;; esac\n' > "$work/stub/ssh"
if out=$(PATH="$work/stub:$PATH" deploy/upgrade-all.sh 0.0.0-st --only n1 2>&1); then fail "sparc accepted"; fi
grep -q 'sparc64' <<< "$out" || fail "arch message: $out"
# a node already on VERSION is skipped
printf '#!/bin/sh\ncase "$*" in *uname*) echo x86_64;; *"otter-node version"*) echo 0.0.0-st;; *) exit 0;; esac\n' > "$work/stub/ssh"
out=$(PATH="$work/stub:$PATH" deploy/upgrade-all.sh 0.0.0-st --only n1 2>&1) || fail "skip run failed: $out"
grep -q 'already 0.0.0-st' <<< "$out" || fail "skip summary: $out"
if out=$(deploy/upgrade-all.sh 0.0.0-st --only nope 2>&1); then fail "unknown --only accepted"; fi
grep -q 'unknown node nope' <<< "$out" || fail "unknown node message: $out"
rm -f dist/otter-node_0.0.0-st_linux_*

# --- push-key.sh: refuses missing/foreign files and unknown hosts before any ssh
if out=$(deploy/push-key.sh n1 /nonexistent.json 2>&1); then fail "push-key with a missing file"; fi
grep -q 'no such file' <<< "$out" || fail "push-key message: $out"
echo '{"type":"authorized_user"}' > "$work/notsa.json"
if out=$(deploy/push-key.sh n1 "$work/notsa.json" 2>&1); then fail "push-key accepted a non-service-account file"; fi
grep -q 'service-account' <<< "$out" || fail "push-key message: $out"
printf '{\n  "type": "service_account",\n  "project_id": "otter-test"\n}\n' > "$work/sa.json"
if out=$(deploy/push-key.sh n2 "$work/sa.json" 2>&1); then fail "push-key without a host"; fi
grep -q 'hosts.sh set n2' <<< "$out" || fail "push-key host message: $out"
if out=$(deploy/push-key.sh n1 2>&1); then fail "push-key without a key argument"; fi
[[ -f "$work/sa.json" ]] || fail "push-key deleted the local key"

# --- status.sh PUSH column (stubbed ssh answers for every remote line)
cat > "$work/stub/ssh" <<'STUB'
#!/bin/sh
printf '0.5.0\nactive\nusers=1\n1M\non\n'
STUB
out=$(PATH="$work/stub:$PATH" deploy/status.sh 2>&1) || true
grep -q '^LABEL .* PUSH$' <<< "$out" || fail "status header: $out"
grep -qE '^n1 .* 1M +on$' <<< "$out" || fail "status push column: $out"

echo "scripts test: ok"
