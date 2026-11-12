#!/usr/bin/env bash
# Offline tests for the admin-side deploy scripts (no VM; ssh/scp are stubs).
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d); trap 'rm -rf "$work"; rm -f dist/otter-node_0.0.0-st_linux_* dist/bundle-n3.* dist/news/0.0.0-st.md' EXIT
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

# --- release-apk.sh / news-dialog.sh with stubbed ssh, scp, apksigner, aapt2 and 'otter-admin announce'
deploy/hosts.sh set n1 root@n1.example
deploy/hosts.sh set n2 root@n2.example 2222
real_admin=$PWD/bin/otter-admin
cat > "$work/stub/apksigner" <<'STUB'
#!/bin/sh
f=$(eval echo "\${$#}")
if grep -q debug "$f"; then echo "Signer #1 certificate DN: C=US, O=Android, CN=Android Debug"; else echo "Signer #1 certificate DN: CN=Otter Release"; fi
STUB
cat > "$work/stub/aapt2" <<'STUB'
#!/bin/sh
f=$(eval echo "\${$#}")
echo "package: name='org.ottermsg' versionCode='6' versionName='$(cut -d' ' -f1 "$f")' platformBuildVersionName='15' platformBuildVersionCode='35'"
STUB
printf '#!/bin/sh\necho "ssh $*" >> "%s/ssh.log"\n' "$work" > "$work/stub/ssh"
printf '#!/bin/sh\necho "scp $*" >> "%s/ssh.log"\ncase "$*" in *"$SCP_FAIL"*) [ -n "$SCP_FAIL" ] && exit 1;; esac\nexit 0\n' "$work" > "$work/stub/scp"
cat > "$work/stub/otter-admin" <<STUB
#!/bin/sh
case " \$* " in
  *" announce "*)
    echo "announce \$*" >> "$work/announce.log"
    prev=""; for a in "\$@"; do case "\$prev" in --ru|--en) echo "text \$prev: \$(cat "\$a")" >> "$work/announce.log";; esac; prev=\$a; done ;;
  *) exec "$real_admin" "\$@" ;;
esac
STUB
chmod +x "$work/stub/"*
export OTTER_ADMIN_BIN="$work/stub/otter-admin"
printf '0.0.0-st debug' > "$work/debug.apk"
printf '0.0.0-st release' > "$work/good.apk"
printf '0.0.0-old release' > "$work/old.apk"
if out=$(PATH="$work/stub:$PATH" deploy/release-apk.sh 0.0.0-st "$work/debug.apk" 2>&1); then fail "debug APK accepted"; fi
grep -q 'debug-signed' <<< "$out" || fail "debug APK message: $out"
if out=$(PATH="$work/stub:$PATH" deploy/release-apk.sh 0.0.0-st "$work/old.apk" 2>&1); then fail "wrong versionName accepted"; fi
grep -q "versionName is '0.0.0-old'" <<< "$out" || fail "versionName message: $out"
[[ ! -e "$work/ssh.log" ]] || fail "refused APK reached ssh/scp"
out=$(PATH="$work/stub:$PATH" deploy/release-apk.sh 0.0.0-st "$work/good.apk" < /dev/null 2>&1) || fail "release-apk: $out"
sha=$(sha256sum "$work/good.apk" | cut -d' ' -f1)
grep -q "^scp -q -P 22 .*good.apk root@n1.example:/tmp/otter-$sha.apk$" "$work/ssh.log" || fail "upload n1: $(cat "$work/ssh.log")"
grep -q "^scp -q -P 2222 .*good.apk root@n2.example:/tmp/otter-$sha.apk$" "$work/ssh.log" || fail "upload n2: $(cat "$work/ssh.log")"
[[ "$(grep -c "^ssh -p .* root@n[12].example /usr/local/bin/otter-node apk import --config /etc/otter/node.toml /tmp/otter-$sha.apk" "$work/ssh.log")" == 2 ]] ||
  fail "apk import: $(cat "$work/ssh.log")"
grep -q "news: deploy/news-dialog.sh 0.0.0-st --apk .*good.apk --version-code 6" <<< "$out" || fail "release-apk news hint: $out"
[[ ! -e "$work/announce.log" ]] || fail "release-apk announced without a terminal"
rm -f "$work/ssh.log"
if out=$(SCP_FAIL=n2.example PATH="$work/stub:$PATH" deploy/release-apk.sh 0.0.0-st "$work/good.apk" --no-news 2>&1); then fail "failed upload ignored"; fi
grep -q 'upload to n2 failed' <<< "$out" || fail "upload failure message: $out"

mkdir -p dist/news
printf '## ru\n\nВышла версия 0.0.0-st.\nОбновите приложение.\n\n## en\nVersion 0.0.0-st is out.\n' > dist/news/0.0.0-st.md
out=$(printf 'o\np\ny\n' | EDITOR=true deploy/news-dialog.sh 0.0.0-st 2>&1) || fail "dialog: $out"
grep -q '^announce .*--ru ' "$work/announce.log" || fail "announce --ru: $(cat "$work/announce.log")"
if grep -q -- '--en\|--apk' "$work/announce.log"; then fail "announce sent more than --ru: $(cat "$work/announce.log")"; fi
grep -q '^text --ru: Вышла версия 0.0.0-st.$' "$work/announce.log" || fail "ru text: $(cat "$work/announce.log")"
rm -f "$work/announce.log"
out=$(printf 'p\np\n' | EDITOR=true deploy/news-dialog.sh 0.0.0-st 2>&1) || fail "dialog skip: $out"
[[ ! -e "$work/announce.log" ]] || fail "skipped dialog announced"
grep -q 'новость не отправлена' <<< "$out" || fail "skip message: $out"
out=$(printf 'о\nо\nн\n' | EDITOR=true deploy/news-dialog.sh 0.0.0-st 2>&1) || fail "dialog no: $out"
[[ ! -e "$work/announce.log" ]] || fail "announced without 'y'"
# Cyrillic answers, both languages, the update; an edit is saved back to the draft
printf '#!/bin/sh\necho "Правка." >> "$1"\n' > "$work/stub/editor"; chmod +x "$work/stub/editor"
out=$(printf 'и\nо\nо\nд\n' | EDITOR="$work/stub/editor" deploy/news-dialog.sh 0.0.0-st --apk "$work/good.apk" --version-code 6 2>&1) ||
  fail "dialog with update: $out"
grep -q -- "^announce .*--ru .* --en .* --apk $work/good.apk --version-name 0.0.0-st --version-code 6" "$work/announce.log" ||
  fail "announce with update: $(cat "$work/announce.log")"
grep -q 'Правка.' dist/news/0.0.0-st.md || fail "edit not saved to the draft: $(cat dist/news/0.0.0-st.md)"
grep -q '^Version 0.0.0-st is out.$' dist/news/0.0.0-st.md || fail "draft lost the English text: $(cat dist/news/0.0.0-st.md)"
rm -f "$work/announce.log" dist/news/0.0.0-st.md
out=$(printf 'n\n' | deploy/news-dialog.sh 0.0.0-st 2>&1) || fail "dialog without a draft: $out"
[[ ! -e "$work/announce.log" && ! -e dist/news/0.0.0-st.md ]] || fail "dialog without a draft sent or created something"
# upgrade-all.sh accepts --no-news (node already on VERSION; no terminal, so no dialog either way)
touch dist/otter-node_0.0.0-st_linux_amd64 dist/otter-node_0.0.0-st_linux_arm64
printf '#!/bin/sh\ncase "$*" in *uname*) echo x86_64;; *"otter-node version"*) echo 0.0.0-st;; *) exit 0;; esac\n' > "$work/stub/ssh"
out=$(PATH="$work/stub:$PATH" deploy/upgrade-all.sh 0.0.0-st --only n1 --no-news 2>&1) || fail "upgrade-all --no-news: $out"
[[ ! -e "$work/announce.log" ]] || fail "upgrade-all announced"
unset OTTER_ADMIN_BIN

echo "scripts test: ok"
