#!/usr/bin/env bash
# Offline tests for the admin-side deploy scripts (no VM; ssh/scp are stubs).
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d); trap 'rm -rf "$work"; rm -f dist/otter-node_0.0.0-st_linux_* dist/otter-node_0.8.0-st_linux_* dist/bundle-n3.* dist/bundle-n1.* dist/bundle-n8.* dist/news/0.0.0-st.md' EXIT
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

# --- add-node.sh dial_out_only question (no terminal here: flags or the default No; stops at the missing release)
mkdir -p "$work/stub"
cat > "$work/stub/admin-log" <<STUB
#!/bin/sh
echo "admin \$*" >> "$work/admin.log"
exec "$PWD/bin/otter-admin" "\$@"
STUB
chmod +x "$work/stub/admin-log"
addnode() { # LABEL FLAG...: runs add-node.sh with logged admin calls; it must stop at the missing release
  local l=$1; shift; rm -f "$work/admin.log"
  if out=$(OTTER_ADMIN_BIN="$work/stub/admin-log" deploy/add-node.sh "$l" "root@$l.example" --ip 192.0.2.9 \
      --version 0.0.0-missing "$@" < /dev/null 2>&1); then fail "add-node $l without release"; fi
  touch "$work/admin.log"
}
addnode n4 --dial-out-only
grep -q 'admin .*node set-dial-out-only --label n4$' "$work/admin.log" || fail "--dial-out-only not set: $(cat "$work/admin.log")"
set_line=$(grep -n 'node set-dial-out-only' "$work/admin.log" | cut -d: -f1)
sign_line=$(grep -n 'manifest sign' "$work/admin.log" | cut -d: -f1)
[[ -n "$sign_line" ]] && (( set_line < sign_line )) || fail "dial_out_only must be set before manifest sign: $(cat "$work/admin.log")"
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node list | grep -q '^n4 .*dial_out_only=true' || fail "n4 not dial_out_only"
addnode n5 --no-dial-out-only
if grep -q 'set-dial-out-only' "$work/admin.log"; then fail "--no-dial-out-only set the flag"; fi
addnode n6
if grep -q 'set-dial-out-only' "$work/admin.log"; then fail "no flag, no terminal: the flag was set"; fi
grep -q 'manifest sign' "$work/admin.log" || fail "n6 not signed: $(cat "$work/admin.log")"
addnode n5 --dial-out-only # a re-run of an existing node never changes the flag
if grep -q 'set-dial-out-only' "$work/admin.log"; then fail "re-run changed dial_out_only"; fi
if out=$(deploy/add-node.sh n7 root@n7 --ip 192.0.2.7 --bogus 2>&1); then fail "unknown flag accepted"; fi
grep -q -- '--dial-out-only' <<< "$out" || fail "add-node usage lacks --dial-out-only: $out"
for l in n4 n5 n6; do bin/otter-admin --dir "$OTTER_ADMIN_DIR" node remove --label "$l" >/dev/null; deploy/hosts.sh rm "$l"; done
bin/otter-admin --dir "$OTTER_ADMIN_DIR" manifest sign >/dev/null
rm -f "$work/admin.log"

# --- upgrade.sh keeps node.toml.prev and restores it on rollback
sed -n "/<<'REMOTE'/,/^REMOTE$/p" deploy/upgrade.sh | sed -n 2,4p | grep -qx 'cd /' || fail "upgrade.sh remote part does not cd / (otter's find fails in /root)"
grep -q '^cp -p /etc/otter/node.toml /etc/otter/node.toml.prev$' deploy/upgrade.sh || fail "upgrade.sh: no node.toml backup"
rollback=$(sed -n '/rolling back/,/^REMOTE$/p' deploy/upgrade.sh)
grep -q '^cp -p /etc/otter/node.toml.prev /etc/otter/node.toml$' <<< "$rollback" || fail "upgrade.sh: rollback does not restore node.toml"

# --- upgrade.sh (remote part, run locally): backup dir 0700, copies 0600, newest 3 pre-upgrade copies (C26)
up="$work/up"; mkdir -p "$up/bin" "$up/etc" "$up/lib" "$up/backups"
printf '#!/bin/sh\nshift 3; exec "$@"\n' > "$up/bin/runuser"
printf '#!/bin/bash\nargs=(); while (($#)); do case "$1" in -o|-g) shift 2;; *) args+=("$1"); shift;; esac; done\nexec /usr/bin/install "${args[@]}"\n' > "$up/bin/install"
cat > "$up/bin/otter-node" <<'STUB'
#!/bin/bash
case "$1" in
  version) echo 0.8.1 ;;
  backup) while (($#)); do [[ "$1" == --out ]] && { umask 022; echo db > "$2"; }; shift; done ;;
esac
STUB
printf '#!/bin/sh\nexit 0\n' > "$up/bin/systemctl"; printf '#!/bin/sh\nexit 0\n' > "$up/bin/health.sh"
chmod +x "$up/bin/"*
cp "$up/bin/otter-node" "$up/bin/otter-node.new"; echo 'x = 1' > "$up/etc/node.toml"
chmod 0755 "$up/backups"
for d in 20250101 20250201 20250301 20250401; do (umask 022; echo old > "$up/backups/pre-upgrade-$d-000000.db"); done
(umask 022; echo daily > "$up/backups/node-2026-11-01.db")
sed -n "/^remote \"\$target\" bash -s -- \"\$sum\" <<'REMOTE'$/,/^REMOTE$/p" deploy/upgrade.sh | sed '1d;$d' |
  sed -e "s#/usr/local/bin/otter-node#$up/bin/otter-node#g" -e "s#/var/backups/otter#$up/backups#g" \
      -e "s#/var/lib/otter#$up/lib#g" -e "s#/etc/otter#$up/etc#g" -e "s#/usr/local/lib/otter/health.sh#health.sh#g" > "$work/upgrade-local.sh"
sum=$(sha256sum "$up/bin/otter-node.new" | cut -d' ' -f1)
PATH="$up/bin:$PATH" bash "$work/upgrade-local.sh" "$sum" > "$work/upgrade-local.out" 2>&1 || fail "upgrade remote part: $(cat "$work/upgrade-local.out")"
[[ "$(stat -c %a "$up/backups")" == 700 ]] || fail "backup dir mode $(stat -c %a "$up/backups")"
[[ -z "$(find "$up/backups" -name '*.db' ! -perm 0600)" ]] || fail "backup files not 0600: $(ls -l "$up/backups")"
[[ "$(ls "$up/backups" | grep -c '^pre-upgrade-')" == 3 ]] || fail "pre-upgrade copies kept: $(ls "$up/backups")"
[[ ! -e "$up/backups/pre-upgrade-20250101-000000.db" && ! -e "$up/backups/pre-upgrade-20250201-000000.db" ]] || fail "oldest copies not pruned"
[[ -e "$up/backups/node-2026-11-01.db" ]] || fail "daily copy pruned"
pr=$(grep -n 'pre-upgrade-\*\.db' deploy/upgrade.sh)
grep -q 'runuser -u otter -- find .* | sort -zr | tail -zn +4 | runuser -u otter -- xargs -0r rm -f --' <<< "$pr" || fail "prune not as otter: $pr"

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
grep -qE '^LABEL .* PUSH +TURN$' <<< "$out" || fail "status header: $out"
grep -qE '^n1 .* 1M +on +-$' <<< "$out" || fail "status push column: $out"
# netlog lines (after the --netlog-- marker) are printed under the table, indented with the label
printf '#!/bin/sh\nprintf "0.7.0\\nactive\\nusers=1\\n1M\\non\\n--netlog--\\n2026-11-20 10:02  fi  reality:192.0.2.5:443  out  ok\\n"\n' > "$work/stub/ssh"
out=$(PATH="$work/stub:$PATH" deploy/status.sh 2>&1) || true
grep -qE '^n1 .* 1M +on +-$' <<< "$out" || fail "status row with netlog: $out"
grep -q '^  n1  2026-11-20 10:02  fi  reality:192.0.2.5:443  out  ok$' <<< "$out" || fail "status netlog: $out"

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
# release-apk uses its own ssh stub: it answers 'version', records the remote command as the remote shell would
# split it, and keeps what arrived on stdin (C3: the APK travels on ssh stdin, never via scp or /tmp)
mkdir -p "$work/stub-apk"
cat > "$work/stub-apk/ssh" <<STUB
#!/bin/bash
echo "ssh \$*" >> "$work/ssh.log"
target=\$3; shift 3
case "\$*" in *"otter-node version"*) echo "\${NODE_VERSION:-0.8.3}"; exit 0 ;; esac
eval "set -- \$*"
printf '%s\n' "\$@" > "$work/remote-\$target.cmd"
cat > "$work/remote-\$target.stdin"
case "\$target" in *"\$SSH_FAIL"*) [ -n "\$SSH_FAIL" ] && exit 1 ;; esac
exit 0
STUB
chmod +x "$work/stub-apk/ssh"
apkpath="$work/stub-apk:$work/stub:$PATH"
if out=$(NODE_VERSION=0.8.1 PATH="$apkpath" deploy/release-apk.sh 0.0.0-st "$work/good.apk" --no-news 2>&1); then fail "release to a 0.8.1 node accepted"; fi
grep -q 'runs otter-node 0.8.1: upgrade it to 0.8.3' <<< "$out" || fail "old node message: $out"
[[ ! -e "$work/remote-root@n1.example.stdin" ]] || fail "APK sent to an old node"
out=$(PATH="$apkpath" deploy/release-apk.sh 0.0.0-st "$work/good.apk" < /dev/null 2>&1) || fail "release-apk: $out"
sha=$(sha256sum "$work/good.apk" | cut -d' ' -f1)
if grep -q '^scp\|/tmp/otter-' "$work/ssh.log"; then fail "release-apk still uses scp or /tmp: $(cat "$work/ssh.log")"; fi
for t in root@n1.example root@n2.example; do
  cmp -s "$work/remote-$t.stdin" "$work/good.apk" || fail "$t: APK not streamed on stdin"
  c="$work/remote-$t.cmd"
  [[ "$(sed -n 1,2p "$c" | tr '\n' ' ')" == "bash -c " ]] || fail "$t: not bash -c: $(cat "$c")"
  grep -qF 'd=$(mktemp -d /root/otter-apk.XXXXXX)' "$c" || fail "$t: no root-only temp dir: $(cat "$c")"
  grep -qF 'sha256sum --quiet -c' "$c" || fail "$t: no checksum: $(cat "$c")"
  grep -qF 'runuser -u otter -- /usr/local/bin/otter-node apk import --config /etc/otter/node.toml - < "$d/app.apk"' "$c" ||
    fail "$t: import not as otter from stdin: $(cat "$c")"
  [[ "$(sed -n 5p "$c")" == "$sha" ]] || fail "$t: sha not passed: $(cat "$c")"
done
grep -q "news: deploy/news-dialog.sh 0.0.0-st --apk .*good.apk --version-code 6" <<< "$out" || fail "release-apk news hint: $out"
[[ ! -e "$work/announce.log" ]] || fail "release-apk announced without a terminal"
# run the remote script itself with stub runuser/otter-node: imported as sent, temp dir removed; a bad sum imports nothing
ra="$work/remote-apk"; mkdir -p "$ra/bin" "$ra/root"
printf '#!/bin/sh\n[ "$1 $2 $3" = "-u otter --" ] || exit 9\nshift 3; exec "$@"\n' > "$ra/bin/runuser"
printf '#!/bin/sh\n[ "$*" = "apk import --config /etc/otter/node.toml -" ] || exit 9\ncat > "%s/imported"\n' "$ra" > "$ra/bin/otter-node"
chmod +x "$ra/bin/"*
script=$(sed -n 3p "$work/remote-root@n1.example.cmd" | sed -e "s#/root/otter-apk#$ra/root/otter-apk#" -e "s#/usr/local/bin/otter-node#otter-node#")
# hostile layout: the node user planted the old predictable upload path as a link to a file of root's
mkdir -p "$ra/tmp"; printf 'root only' > "$ra/victim"; ln -s "$ra/victim" "$ra/tmp/otter-$sha.apk"
TMPDIR="$ra/tmp" PATH="$ra/bin:$PATH" bash -c "$script" import "$sha" < "$work/good.apk" || fail "remote script failed"
cmp -s "$ra/imported" "$work/good.apk" || fail "remote script: imported bytes differ"
[[ -z "$(ls -A "$ra/root")" ]] || fail "remote script left its temp dir"
[[ "$(cat "$ra/victim")" == 'root only' ]] || fail "remote script wrote through the planted link"
rm -f "$ra/imported"
if PATH="$ra/bin:$PATH" bash -c "$script" import "$(printf '0%.0s' {1..64})" < "$work/good.apk" >/dev/null 2>&1; then fail "bad sum accepted"; fi
[[ ! -e "$ra/imported" ]] || fail "bad sum imported"
[[ -z "$(ls -A "$ra/root")" ]] || fail "remote script left its temp dir after a bad sum"
rm -f "$work/ssh.log" "$work"/remote-root@*
if out=$(SSH_FAIL=n2.example PATH="$apkpath" deploy/release-apk.sh 0.0.0-st "$work/good.apk" --no-news 2>&1); then fail "failed import ignored"; fi
grep -q 'apk import on n2 failed' <<< "$out" || fail "import failure message: $out"

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

# --- reality-setup.sh (stubbed ssh: the remote script's stdin is saved, its stdout is the public key)
if out=$(deploy/reality-setup.sh n1 2>&1); then fail "reality-setup without --dest"; fi
grep -q -- '--dest' <<< "$out" || fail "reality-setup usage: $out"
if out=$(deploy/reality-setup.sh n1 --dest 'bad host;rm' 2>&1); then fail "reality-setup accepted a bad --dest"; fi
deploy/hosts.sh rm n2
if out=$(deploy/reality-setup.sh n2 --dest www.example.com 2>&1); then fail "reality-setup without a host"; fi
grep -q 'hosts.sh set n2' <<< "$out" || fail "reality-setup host message: $out"
pub=$(head -c32 /dev/zero | base64 | tr '+/' '-_' | tr -d '=')
cat > "$work/stub/ssh" <<STUB
#!/bin/sh
echo "ssh \$*" >> "$work/ssh.log"
case "\$*" in
  *reality-check*) [ -z "\$CHECK_FAIL" ] || exit 1 ;;
  *"bash -s"*) cat > "$work/remote.sh"; [ -z "\$REMOTE_FAIL" ] || exit 1; echo "$pub" ;;
esac
STUB
rm -f "$work/ssh.log"
if out=$(CHECK_FAIL=1 PATH="$work/stub:$PATH" deploy/reality-setup.sh n1 --dest www.example.com 2>&1); then fail "failed camouflage check accepted"; fi
grep -q 'failed the check' <<< "$out" || fail "reality-check message: $out"
if grep -q 'bash -s' "$work/ssh.log"; then fail "configured REALITY after a failed check"; fi
if out=$(REMOTE_FAIL=1 PATH="$work/stub:$PATH" deploy/reality-setup.sh n1 --dest www.example.com 2>&1); then fail "remote failure ignored"; fi
grep -q 'previous config' <<< "$out" || fail "remote failure message: $out"
if bin/otter-admin --dir "$OTTER_ADMIN_DIR" node list | grep -q REALITY; then fail "endpoint added after a failed setup"; fi
out=$(PATH="$work/stub:$PATH" deploy/reality-setup.sh n1 --dest www.example.com 2>&1) || fail "reality-setup: $out"
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node list | grep -q '^n1 .*REALITY 192.0.2.1:443.* sni=www.example.com' ||
  fail "REALITY endpoint: $(bin/otter-admin --dir "$OTTER_ADMIN_DIR" node list)"
grep -q 'manifest sign' <<< "$out" || fail "reality-setup next steps: $out"
grep -q '^ssh -p 22 .*root@n1.example /usr/local/bin/otter-node reality-check www.example.com$' "$work/ssh.log" || fail "check call: $(cat "$work/ssh.log")"
for want in 'otter-node check --config /etc/otter/node.toml.new' 'reality keygen --config /etc/otter/node.toml.new' \
    'CAP_NET_BIND_SERVICE' '"reality on"' 'node.toml.pre-reality /etc/otter/node.toml' '--force'; do
  grep -qF -- "$want" "$work/remote.sh" || fail "remote script lacks $want"
done
bash -n "$work/remote.sh" || fail "remote script syntax"
grep -q '^CapabilityBoundingSet=CAP_NET_BIND_SERVICE$' deploy/templates/otter-node.service &&
  grep -q '^AmbientCapabilities=CAP_NET_BIND_SERVICE$' deploy/templates/otter-node.service || fail "unit lacks CAP_NET_BIND_SERVICE"

# --- M8: TURN relay for calls (D77) ------------------------------------------------------------------------------
# lib.sh version_ge: releases only (dev builds and "unknown" are not 0.8.0+)
(
  source deploy/lib.sh
  for v in 0.8.0 0.8.0-st 0.8.1 0.10.0 1.0.0; do version_ge "$v" 0.8.0 || fail "version_ge $v"; done
  for v in 0.7.0 0.7.9 0.0.0-st dev-abc123 unknown ""; do if version_ge "$v" 0.8.0; then fail "version_ge accepted '$v'"; fi; done
) || exit 1
# templates and install.sh (static: install.sh runs only on a real server)
grep -q '^relay_ip = "\${OTTER_IP}"$' deploy/templates/node.toml.turn || fail "turn template relay_ip"
grep -q '^\[turn\]$' deploy/templates/node.toml.turn && grep -q '^enabled = true$' deploy/templates/node.toml.turn || fail "turn template"
if grep -q '^\[turn\]' deploy/templates/node.toml; then fail "[turn] in the base template (pre-0.8.0 bundles)"; fi
grep -q '^RestrictAddressFamilies=.*AF_NETLINK' deploy/templates/otter-node.service || fail "unit template: TURN needs AF_NETLINK"
grep -q 'otter-node turn keygen --config /etc/otter/node.toml$' deploy/bundle/install.sh || fail "install.sh does not create the TURN secret"
keygen_line=$(grep -n 'otter-node turn keygen' deploy/bundle/install.sh | cut -d: -f1)
check_line=$(grep -n 'otter-node check --config' deploy/bundle/install.sh | cut -d: -f1)
bin_line=$(grep -n 'install -o root -g root -m 0755 "otter-node-\$arch"' deploy/bundle/install.sh | cut -d: -f1)
(( bin_line < keygen_line && keygen_line < check_line )) || fail "install.sh: keygen must run after the binary install and before check"
grep -q 'chown root:otter /etc/otter/turn.secret && chmod 0640 /etc/otter/turn.secret' deploy/bundle/install.sh || fail "install.sh secret mode"
grep -q '49160:49200/udp' deploy/bundle/install.sh || fail "install.sh firewall: relay range"
grep -q 'if \[\[ "\$turn_ufw" == 1 \]\]; then' deploy/bundle/install.sh || fail "install.sh changes ufw for TURN without a yes"
grep -q 'cloud firewall: also open UDP 3478, TCP 3478, TCP 5349, UDP 49160-49200' deploy/bundle/install.sh || fail "install.sh cloud reminder"
grep -q 'OTTER_TURN_UFW=\$turn_ufw ./bundle-' deploy/push.sh || fail "push.sh does not pass the ufw answer"

# --- root-run steps never write into the node user's directories (C3 class, D82)
grep -nH '/var/lib/otter\|/var/backups/otter' deploy/bundle/install.sh deploy/upgrade.sh deploy/release-apk.sh |
  grep -v -e 'runuser -u otter --' -e 'install -d -o otter -g otter -m 0700 /var/\(lib\|backups\)/otter$' \
    -e ':backup=/var/backups/otter/pre-upgrade-' -e ':  useradd --system --home-dir /var/lib/otter --no-create-home ' \
    > "$work/rootwrites" || true
[[ ! -s "$work/rootwrites" ]] || fail "root-run lines touching otter's directories: $(cat "$work/rootwrites")"
grep -qF 'runuser -u otter -- /usr/local/bin/otter-node import --config /etc/otter/node.toml - < "$f"' deploy/bundle/install.sh ||
  fail "install.sh: invites not imported as otter from stdin"
# The same, executed: install.sh and the upgrade.sh rollback run against a fake root. A guard stands in for the
# root/otter split: every file tool refuses to act as root (no OTTER_AS=otter) on a path inside otter's directories,
# and only 'runuser -u otter --' sets OTTER_AS=otter. The node user plants links; the deploy steps must not follow them.
fr="$work/fakeroot"
mkdir -p "$fr/bin" "$fr/etc/otter" "$fr/etc/systemd/system" "$fr/var/lib" "$fr/var/backups" "$fr/usr/local/bin" \
  "$fr/usr/local/lib/otter" "$fr/bundle/site/css" "$fr/bundle/invites"
for t in install cp tar mkdir chown chmod rm ln mv touch; do
  cat > "$fr/bin/$t" <<STUB
#!/bin/bash
if [ "\$OTTER_AS" != otter ]; then
  for a in "\$@"; do case "\$a" in "$fr/var/lib/otter/"*|"$fr/var/backups/otter/"*) echo "root $t \$*" >> "$fr/violations"; exit 1 ;; esac; done
fi
[ $t = chown ] && exit 0  # not root here: ownership is the guard's job
args=(); skip=0
for a in "\$@"; do if ((skip)); then skip=0; elif [ $t = install ] && [[ "\$a" == -[og] ]]; then skip=1; else args+=("\$a"); fi; done
exec $(command -v $t) "\${args[@]}"
STUB
done
printf '#!/bin/sh\n[ "$1 $2 $3" = "-u otter --" ] || exit 9\nshift 3; OTTER_AS=otter exec "$@"\n' > "$fr/bin/runuser"
printf '#!/bin/sh\ncase "$1" in is-active) [ "$3" = chrony ] ;; esac\n' > "$fr/bin/systemctl"
printf '#!/bin/sh\necho yes\n' > "$fr/bin/timedatectl"
printf '#!/bin/sh\nexit 0\n' > "$fr/bin/id"
printf '#!/bin/sh\nexit 0\n' > "$fr/bin/ss"
printf '#!/bin/sh\necho x86_64\n' > "$fr/bin/uname"
printf '#!/bin/sh\necho "Status: inactive"\n' > "$fr/bin/ufw"
chmod +x "$fr/bin/"*
printf 'ID=debian\n' > "$fr/etc/os-release"
paths=(-e "s#/etc/otter#$fr/etc/otter#g" -e "s#/etc/os-release#$fr/etc/os-release#g" -e "s#/etc/systemd/system#$fr/etc/systemd/system#g"
  -e "s#/var/lib/otter#$fr/var/lib/otter#g" -e "s#/var/backups/otter#$fr/var/backups/otter#g"
  -e "s#/usr/local/bin/#$fr/usr/local/bin/#g" -e "s#/usr/local/lib/otter#$fr/usr/local/lib/otter#g")
b="$fr/bundle"
sed "${paths[@]}" -e 's/\$EUID -eq 0/0 -eq 0/' deploy/bundle/install.sh > "$b/install.sh"
# the node binary: imports what arrives on stdin (as otter only), reports itself, backs up per $BACKUP_MODE
cat > "$b/otter-node-amd64" <<STUB
#!/bin/bash
case "\$1" in
  version) echo 0.8.3 ;;
  check) exit 0 ;;
  import) [ "\$OTTER_AS" = otter ] && [ "\${@: -1}" = - ] || exit 9; cat >> "$fr/imported" ;;
  backup) out=\${@: -1}; if [ "\$BACKUP_MODE" = link ]; then ln -s "$fr/rootsecret" "\$out"; else echo db-copy > "\$out"; fi ;;
esac
STUB
printf '#!/bin/sh\nexit 0\n' > "$b/health.sh"
chmod +x "$b/otter-node-amd64" "$b/health.sh" "$b/install.sh"
for f in node.key tls.key manifest.bin tls.crt uninstall.sh backup.sh harden-report.sh otter-node.service otter-backup.service otter-backup.timer; do echo "$f" > "$b/$f"; done
printf 'data_dir = "/var/lib/otter"\n' > "$b/node.toml"
printf 'OTTER_PORT=27443\nOTTER_PROBE_URL=https://192.0.2.1:27443/\n' > "$b/probe.env"
echo '<html>decoy</html>' > "$b/site/index.html"; echo 'body{}' > "$b/site/css/a.css"
printf 'invite-1' > "$b/invites/a.bin"
(cd "$b" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
fakeinstall() { rm -f "$fr/violations" "$fr/imported"; (cd "$b" && PATH="$fr/bin:$PATH" bash ./install.sh) > "$work/install.out" 2>&1; }
fakeinstall || fail "fake-root install: $(cat "$work/install.out" "$fr/violations" 2>/dev/null)"
[[ ! -e "$fr/violations" ]] || fail "install.sh as root inside otter's directories: $(cat "$fr/violations")"
cmp -s "$fr/var/lib/otter/site/css/a.css" "$b/site/css/a.css" || fail "install.sh did not unpack the site"
[[ "$(cat "$fr/imported")" == invite-1 ]] || fail "invite not imported on otter's stdin"
if compgen -G "$fr/var/lib/otter/import-*" >/dev/null; then fail "invite copied into otter's directory"; fi
# hostile layout: otter replaced its site directory with a link to a directory of root's (read-only for otter)
mkdir -p "$fr/victim"; chmod 0555 "$fr/victim"
mv "$fr/var/lib/otter/site" "$fr/var/lib/otter/site.real"; ln -s "$fr/victim" "$fr/var/lib/otter/site"
if fakeinstall; then fail "install.sh followed the planted site link"; fi
[[ ! -e "$fr/violations" ]] || fail "install.sh as root inside otter's directories: $(cat "$fr/violations")"
[[ -z "$(ls -A "$fr/victim")" && "$(stat -c %a "$fr/victim")" == 555 ]] || fail "the link target was changed"
chmod 0755 "$fr/victim"; rm "$fr/var/lib/otter/site"; mv "$fr/var/lib/otter/site.real" "$fr/var/lib/otter/site"
# upgrade.sh rollback (health check fails once): the pre-upgrade copy is restored by otter, never by root
sed -n "/<<'REMOTE'$/,/^REMOTE$/p" deploy/upgrade.sh | sed -e 1d -e '$d' | sed "${paths[@]}" > "$fr/upgrade-remote.sh"
printf '#!/bin/sh\n[ -e "%s/healthy-once" ] && exit 0; touch "%s/healthy-once"; exit 1\n' "$fr" "$fr" > "$fr/usr/local/lib/otter/health.sh"
chmod +x "$fr/usr/local/lib/otter/health.sh"
printf 'secret of root' > "$fr/rootsecret"; chmod 0000 "$fr/rootsecret"
fakeupgrade() {
  rm -f "$fr/violations" "$fr/healthy-once" "$fr/var/lib/otter/node.db" "$fr/var/backups/otter/"*; cp "$b/otter-node-amd64" "$fr/usr/local/bin/otter-node.new"
  cp "$b/node.toml" "$fr/etc/otter/node.toml"
  if [[ -n "${PLANT:-}" ]]; then  # otter's own layout: old 0644 copies and a link to root's file among them
    for d in 1 2 3 4; do (umask 022; echo old > "$fr/var/backups/otter/pre-upgrade-2025010$d-000000.db"); done
    ln -s "$fr/rootsecret" "$fr/var/backups/otter/node-planted.db"
  fi
  PATH="$fr/bin:$PATH" bash "$fr/upgrade-remote.sh" "$(sha256sum "$fr/usr/local/bin/otter-node.new" | cut -d' ' -f1)" > "$work/upgrade.out" 2>&1
}
rc=0; BACKUP_MODE=file fakeupgrade || rc=$?
[[ $rc == 2 ]] || fail "fake-root rollback exit $rc: $(cat "$work/upgrade.out" "$fr/violations" 2>/dev/null)"
[[ ! -e "$fr/violations" ]] || fail "upgrade.sh rollback as root inside otter's directories: $(cat "$fr/violations")"
[[ "$(cat "$fr/var/lib/otter/node.db")" == db-copy && "$(stat -c %a "$fr/var/lib/otter/node.db")" == 600 ]] ||
  fail "rollback did not restore the copy 0600"
# hostile layout: the 'backup' is otter's link to a file only root may read; the rollback must not copy it out
rc=0; BACKUP_MODE=link fakeupgrade || rc=$?
[[ $rc != 0 ]] || fail "rollback restored through a planted link"
[[ ! -e "$fr/violations" ]] || fail "upgrade.sh rollback as root inside otter's directories: $(cat "$fr/violations")"
if grep -qs 'secret of root' "$fr/var/lib/otter/node.db"; then fail "rollback handed root's file to otter"; fi
# hostile layout: the 0600 pass and the pruning (C26) run as otter and never chmod through otter's planted link
rc=0; PLANT=1 BACKUP_MODE=file fakeupgrade || rc=$?
[[ $rc == 2 ]] || fail "fake-root upgrade with planted copies exit $rc: $(cat "$work/upgrade.out" "$fr/violations" 2>/dev/null)"
[[ ! -e "$fr/violations" ]] || fail "upgrade.sh as root inside otter's directories: $(cat "$fr/violations")"
[[ "$(stat -c %a "$fr/rootsecret")" == 0 ]] || fail "the 0600 pass changed root's file through a link"
[[ "$(stat -c %a "$fr/var/backups/otter")" == 700 ]] || fail "fake-root backup dir mode $(stat -c %a "$fr/var/backups/otter")"
[[ "$(find "$fr/var/backups/otter" -name 'pre-upgrade-*' -type f | wc -l)" == 3 && -z "$(find "$fr/var/backups/otter" -type f ! -perm 0600)" ]] ||
  fail "fake-root copies after upgrade: $(ls -l "$fr/var/backups/otter")"
chmod 0600 "$fr/rootsecret"

# make-bundle.sh: [turn] with the node's IP only for 0.8.0+
printf 'fake' > dist/otter-node_0.8.0-st_linux_amd64; printf 'fake' > dist/otter-node_0.8.0-st_linux_arm64
touch dist/otter-node_0.0.0-st_linux_amd64 dist/otter-node_0.0.0-st_linux_arm64
deploy/make-bundle.sh n1 0.8.0-st >/dev/null || fail "make-bundle 0.8.0-st"
toml=$(tar -xzOf dist/bundle-n1.tar.gz bundle-n1/node.toml)
grep -q '^\[turn\]$' <<< "$toml" || fail "0.8.0 bundle without [turn]: $toml"
grep -q '^relay_ip = "192.0.2.1"$' <<< "$toml" || fail "0.8.0 bundle relay_ip: $toml"
[[ "$(grep -c '^\[' <<< "$toml")" == "$(grep '^\[' <<< "$toml" | sort -u | wc -l)" ]] || fail "duplicate sections: $toml"
if grep -q 'turn.secret$' <<< "$(tar -tzf dist/bundle-n1.tar.gz)"; then fail "a TURN secret in the bundle"; fi
rm -f dist/bundle-n1.*
deploy/make-bundle.sh n1 0.0.0-st >/dev/null || fail "make-bundle 0.0.0-st"
if grep -q 'turn' <<< "$(tar -xzOf dist/bundle-n1.tar.gz bundle-n1/node.toml)"; then fail "pre-0.8.0 bundle has [turn]"; fi
rm -f dist/bundle-n1.*
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node add --label n8 --wss-host 192.0.2.8 >/dev/null # no --ip: no relay_ip
if out=$(deploy/make-bundle.sh n8 0.8.0-st 2>&1); then fail "0.8.0 bundle without an IPv4"; fi
grep -q 'set-ip --label n8' <<< "$out" || fail "make-bundle no-IP message: $out"
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node remove --label n8 >/dev/null
rm -f dist/otter-node_0.0.0-st_linux_*

# turn-setup.sh with stubbed ssh: probe answers "$VER / $HAS / $FW"; the remote script's stdin is saved
if out=$(deploy/turn-setup.sh 2>&1); then fail "turn-setup without a label"; fi
grep -q 'usage: turn-setup.sh LABEL' <<< "$out" || fail "turn-setup usage: $out"
if out=$(deploy/turn-setup.sh n1 --bogus 2>&1); then fail "turn-setup accepted --bogus"; fi
if out=$(deploy/turn-setup.sh n2 2>&1); then fail "turn-setup without a host"; fi
grep -q 'hosts.sh set n2' <<< "$out" || fail "turn-setup host message: $out"
cat > "$work/stub/ssh" <<STUB
#!/bin/sh
echo "ssh \$*" >> "$work/ssh.log"
case "\$*" in
  *"ufw status"*) printf '%s\n%s\n%s\n' "\${PVER:-\${VER:-0.8.0}}" "\${HAS:-no-turn}" "\${FW:-no-ufw}" ;;
  *uname*) echo x86_64 ;;
  *"otter-node version"*) echo "\${VER:-0.8.0}" ;;
  *"bash -s"*) cat > "$work/turn-remote.sh"; [ -z "\$REMOTE_FAIL" ] || exit 1; echo "TURN is on" ;;
esac
STUB
chmod +x "$work/stub/ssh"
tsetup() { rm -f "$work/ssh.log" "$work/turn-remote.sh"; touch "$work/ssh.log"; PATH="$work/stub:$PATH" deploy/turn-setup.sh "$@" < /dev/null 2>&1; }
out=$(tsetup n1) || fail "turn-setup: $out"
grep -q '^ssh -p 22 .*root@n1.example bash -s -- 192.0.2.1 0 0 0$' "$work/ssh.log" || fail "turn-setup remote call: $(cat "$work/ssh.log")"
grep -q 'cloud firewall, open there: UDP 3478, TCP 3478, TCP 5349, UDP 49160-49200' <<< "$out" || fail "turn-setup cloud reminder: $out"
r="$work/turn-remote.sh"
bash -n "$r" || fail "turn-setup remote script syntax"
for want in 'otter-node check --config /etc/otter/node.toml.new' 'turn keygen --config /etc/otter/node.toml.new' \
    'cp -p "$cfg" /etc/otter/node.toml.pre-turn' 'mv /etc/otter/node.toml.pre-turn "$cfg"' '"msg":"turn on"' \
    'relay_ip = "$relay_ip"' 'chmod 0640 /etc/otter/turn.secret' 'RestrictAddressFamilies=AF_NETLINK' \
    'systemctl daemon-reload'; do
  grep -qF -- "$want" "$r" || fail "turn-setup remote script lacks $want"
done
for v in 0.7.0 dev-abc123; do
  if out=$(VER=$v tsetup n1); then fail "turn-setup accepted $v"; fi
  grep -q 'needs 0.8.0' <<< "$out" || fail "turn-setup old-version message: $out"
  if grep -q 'bash -s' "$work/ssh.log"; then fail "turn-setup configured a $v node"; fi
done
out=$(HAS=turn tsetup n1 --if-missing) || fail "turn-setup --if-missing with [turn]: $out"
grep -q 'already has \[turn\]' <<< "$out" || fail "--if-missing message: $out"
if grep -q 'bash -s' "$work/ssh.log"; then fail "--if-missing reconfigured"; fi
if out=$(HAS=turn tsetup n1); then fail "turn-setup replaced [turn] without --force"; fi
grep -q -- '--force' <<< "$out" || fail "turn-setup --force hint: $out"
out=$(HAS=turn tsetup n1 --force) || fail "turn-setup --force: $out"
grep -q 'bash -s -- 192.0.2.1 1 0 0$' "$work/ssh.log" || fail "--force not passed: $(cat "$work/ssh.log")"
# an active ufw without a terminal: not changed, the commands are printed
out=$(FW=ufw tsetup n1) || fail "turn-setup with ufw: $out"
grep -q 'bash -s -- 192.0.2.1 0 0 0$' "$work/ssh.log" || fail "ufw changed without a yes: $(cat "$work/ssh.log")"
grep -q 'NOT be changed.*ufw allow 3478/udp && ufw allow 3478/tcp && ufw allow 5349/tcp && ufw allow 49160:49200/udp' <<< "$out" ||
  fail "ufw commands not printed: $out"
if out=$(REMOTE_FAIL=1 tsetup n1); then fail "turn-setup ignored a remote failure"; fi
grep -q 'previous config' <<< "$out" || fail "turn-setup failure message: $out"

# the remote script itself, run against a fake /etc/otter with stub tools
fake="$work/fake"; mkdir -p "$fake/bin" "$fake/etc"
cat > "$fake/bin/otter-node" <<STUB
#!/bin/sh
case "\$1" in
  version) echo 0.8.0 ;;
  turn) [ -f "$fake/etc/turn.secret" ] && exit 1; head -c32 /dev/urandom > "$fake/etc/turn.secret"; echo "turn secret written $fake/etc/turn.secret" ;;
  check) [ -z "\$CHECK_FAIL" ] || { echo "config: bad" >&2; exit 1; }; grep -q '^relay_ip = "192.0.2.1"' "\$3" ;;
esac
STUB
printf '#!/bin/sh\nshift 3; exec "$@"\n' > "$fake/bin/runuser"
printf '#!/bin/sh\nexit 0\n' > "$fake/bin/chown"
printf '#!/bin/sh\necho "systemctl $*" >> "%s/actions.log"\n' "$fake" > "$fake/bin/systemctl"
printf '#!/bin/sh\n[ -n "$TURN_FAIL" ] && echo "{\\"msg\\":\\"turn off: could not start\\"}" || echo "{\\"msg\\":\\"turn on\\"}"\n' > "$fake/bin/journalctl"
printf '#!/bin/sh\ncase "$1" in status) echo "Status: active";; *) echo "ufw $*" >> "%s/actions.log";; esac\n' "$fake" > "$fake/bin/ufw"
printf '#!/bin/sh\nexit 0\n' > "$fake/bin/health.sh"
chmod +x "$fake/bin/"*
sed -e "s#/etc/otter#$fake/etc#g" -e "s#/etc/systemd/system#$fake/systemd#g" -e 's#/usr/local/bin/otter-node#otter-node#g' \
  -e 's#/usr/local/lib/otter/health.sh#health.sh#g' "$r" > "$work/turn-local.sh"
mkdir -p "$fake/systemd"; printf '[Service]\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n' > "$fake/systemd/otter-node.service"
orig=$'data_dir = "/var/lib/otter"\n\n[wss]\nlisten = ":27443"\n\n[push]\nfcm_credentials = "/etc/otter/fcm.json"'
runremote() { rm -f "$fake/actions.log"; PATH="$fake/bin:$PATH" bash "$work/turn-local.sh" "$@" 2>&1; }
printf '%s\n' "$orig" > "$fake/etc/node.toml"
out=$(runremote 192.0.2.1 0 0 1) || fail "remote script: $out"
cfg=$(cat "$fake/etc/node.toml")
grep -q '^relay_ip = "192.0.2.1"$' <<< "$cfg" && grep -q '^enabled = true$' <<< "$cfg" || fail "remote: no [turn]: $cfg"
grep -q '^fcm_credentials' <<< "$cfg" || fail "remote lost [push]: $cfg"
grep -qx 'RestrictAddressFamilies=AF_NETLINK' "$fake/systemd/otter-node.service.d/netlink.conf" || fail "remote: no AF_NETLINK drop-in"
grep -q '^systemctl daemon-reload' "$fake/actions.log" || fail "remote: no daemon-reload after the drop-in"
[[ "$(cat "$fake/etc/node.toml.pre-turn")" == "$orig" ]] || fail "remote: node.toml.pre-turn is not the old config"
[[ "$(stat -c %a "$fake/etc/turn.secret")" == 640 && "$(stat -c %s "$fake/etc/turn.secret")" == 32 ]] || fail "secret mode/size"
[[ "$(grep -c '^ufw allow' "$fake/actions.log")" == 4 ]] || fail "ufw rules after a yes: $(cat "$fake/actions.log")"
grep -q '^+ ufw allow 49160:49200/udp$' <<< "$out" || fail "ufw commands not printed: $out"
[[ ! -e "$fake/etc/node.toml.new" ]] || fail "node.toml.new left behind"
secret_hex=$(od -An -tx1 "$fake/etc/turn.secret" | tr -d ' \n')
if grep -qF "$secret_hex" <<< "$(od -An -tx1 <<< "$out" | tr -d ' \n')"; then fail "the secret was printed"; fi
if grep -qE '(^|[;|&( ])(cat|od|xxd|base64|scp|head|tail|less) [^#]*turn\.secret' "$r" deploy/turn-setup.sh deploy/bundle/install.sh; then fail "a script reads the secret out"; fi
# --force replaces the section once and keeps the secret and the sections after it
printf '%s\n' "$orig" > "$fake/etc/node.toml"
printf '\n# Embedded TURN relay for calls (M8, D77), old.\n[turn]\nenabled = true\nrelay_ip = "198.51.100.1"\n\n[limits]\nmax_blob = "50MiB"\n' >> "$fake/etc/node.toml"
cp "$fake/etc/turn.secret" "$work/secret.before"
if out=$(runremote 192.0.2.1 0 0 0); then fail "remote replaced [turn] without force"; fi
out=$(runremote 192.0.2.1 0 1 0) || fail "remote --if-missing: $out"
grep -q '198.51.100.1' "$fake/etc/node.toml" || fail "--if-missing changed the config"
out=$(runremote 192.0.2.1 1 0 0) || fail "remote --force: $out"
cfg=$(cat "$fake/etc/node.toml")
[[ "$(grep -c '^\[turn\]' <<< "$cfg")" == 1 && "$(grep -c '^# Embedded TURN relay' <<< "$cfg")" == 1 ]] || fail "--force duplicated [turn]: $cfg"
if grep -q '198.51.100.1' <<< "$cfg"; then fail "--force kept the old relay_ip: $cfg"; fi
grep -q '^max_blob = "50MiB"$' <<< "$cfg" || fail "--force dropped [limits]: $cfg"
cmp -s "$fake/etc/turn.secret" "$work/secret.before" || fail "--force replaced the secret"
[[ ! -e "$fake/actions.log" ]] || ! grep -q '^ufw' "$fake/actions.log" || fail "ufw changed without a yes"
# a config otter-node check rejects: live node.toml untouched, no restart
printf '%s\n' "$orig" > "$fake/etc/node.toml"; rm -f "$fake/etc/node.toml.pre-turn"
if out=$(CHECK_FAIL=1 runremote 192.0.2.1 0 0 1); then fail "remote ignored a failed check"; fi
[[ "$(cat "$fake/etc/node.toml")" == "$orig" && ! -e "$fake/etc/node.toml.pre-turn" && ! -e "$fake/etc/node.toml.new" ]] ||
  fail "failed check changed the config"
[[ ! -e "$fake/actions.log" ]] || fail "failed check restarted or touched ufw: $(cat "$fake/actions.log")"
# TURN does not come up: rolled back to the previous config, no firewall change
if out=$(TURN_FAIL=1 runremote 192.0.2.1 0 0 1); then fail "remote ignored a TURN start failure"; fi
[[ "$(cat "$fake/etc/node.toml")" == "$orig" ]] || fail "no rollback: $(cat "$fake/etc/node.toml")"
[[ "$(grep -c '^systemctl restart otter-node$' "$fake/actions.log")" == 2 ]] || fail "rollback restarts: $(cat "$fake/actions.log")"
if grep -q '^ufw' "$fake/actions.log"; then fail "ufw changed although TURN failed"; fi

# upgrade-all.sh runs turn-setup --if-missing after 0.8.0+ (also for nodes already on it), unless --no-turn
grep -q '"\$ROOT/deploy/turn-setup.sh" "\$1" --if-missing' deploy/upgrade-all.sh || fail "upgrade-all does not call turn-setup"
touch dist/otter-node_0.8.0-st_linux_amd64 dist/otter-node_0.8.0-st_linux_arm64
rm -f "$work/ssh.log"
out=$(VER=0.8.0-st PATH="$work/stub:$PATH" deploy/upgrade-all.sh 0.8.0-st --only n1 --no-news < /dev/null 2>&1) || fail "upgrade-all turn: $out"
grep -q 'bash -s -- 192.0.2.1 0 1 0$' "$work/ssh.log" || fail "upgrade-all did not run turn-setup: $(cat "$work/ssh.log")"
grep -q '^n1 .*already 0.8.0-st, TURN ok$' <<< "$out" || fail "upgrade-all TURN summary: $out"
rm -f "$work/ssh.log"
# a real upgrade (upgrade.sh's remote script is stubbed too), then TURN
out=$(VER=0.7.0 PVER=0.8.0-st PATH="$work/stub:$PATH" deploy/upgrade-all.sh 0.8.0-st --only n1 --no-news < /dev/null 2>&1) ||
  fail "upgrade-all upgrade + turn: $out"
grep -q '^n1 .*upgraded 0.7.0 → 0.8.0-st, TURN ok$' <<< "$out" || fail "upgrade-all upgrade + TURN summary: $out"
[[ "$(grep -c 'bash -s' "$work/ssh.log")" == 2 ]] && grep -q 'bash -s -- 192.0.2.1 0 1 0$' "$work/ssh.log" ||
  fail "upgrade then turn-setup: $(cat "$work/ssh.log")"
rm -f "$work/ssh.log"
out=$(VER=0.8.0-st REMOTE_FAIL=1 PATH="$work/stub:$PATH" deploy/upgrade-all.sh 0.8.0-st --only n1 --no-news < /dev/null 2>&1) ||
  fail "upgrade-all must not stop on a TURN failure: $out"
grep -q '^n1 .*TURN NOT ENABLED$' <<< "$out" || fail "upgrade-all TURN failure summary: $out"
rm -f "$work/ssh.log"
out=$(VER=0.8.0-st PATH="$work/stub:$PATH" deploy/upgrade-all.sh 0.8.0-st --only n1 --no-news --no-turn < /dev/null 2>&1) || fail "--no-turn: $out"
if grep -q 'ufw status\|bash -s' "$work/ssh.log"; then fail "--no-turn ran turn-setup: $(cat "$work/ssh.log")"; fi
grep -q '^n1 .*already 0.8.0-st$' <<< "$out" || fail "--no-turn summary: $out"
rm -f "$work/ssh.log" dist/otter-node_0.8.0-st_linux_*

# status.sh TURN column and the turn_allocs stats suffix
cat > "$work/stub/ssh" <<'STUB'
#!/bin/sh
printf '0.8.0\nactive\nusers=1 turn_allocs=2 turn_relayed_bytes=10\n1M\non\non\n--netlog--\n'
STUB
out=$(PATH="$work/stub:$PATH" deploy/status.sh 2>&1) || true
grep -qE '^LABEL .* PUSH +TURN$' <<< "$out" || fail "status header: $out"
grep -qE '^n1 .*users=1 turn_allocs=2 turn_relayed_bytes=10 .* on +on$' <<< "$out" || fail "status TURN column: $out"
printf '#!/bin/sh\nprintf "0.8.0\\nactive\\nusers=1\\n1M\\non\\noff\\n--netlog--\\n"\n' > "$work/stub/ssh"
out=$(PATH="$work/stub:$PATH" deploy/status.sh 2>&1) || true
grep -qE '^n1 .* on +off$' <<< "$out" || fail "status TURN off: $out"
grep -q 'grep -q "^\\\[turn\\\]" /etc/otter/node.toml' deploy/status.sh || fail "status.sh does not check [turn]"


# --- status.sh health block (otter-node status --line, 0.10.1+) inside the single SSH call; problems fail the run.
# A probe stub answers the hello so the exit code reflects the health block alone.
printf '#!/bin/sh\nexit 0\n' > "$work/stub/node-ok"; chmod +x "$work/stub/node-ok"
grep -q 'echo --status--; runuser -u otter -- /usr/local/bin/otter-node status --config /etc/otter/node.toml --line' deploy/status.sh ||
  fail "status.sh does not run otter-node status in its SSH call"
[[ "$(grep -c 'remote "\$TARGET"' deploy/status.sh)" == 1 ]] || fail "status.sh must keep one SSH call per node"
cat > "$work/stub/ssh" <<'STUB'
#!/bin/sh
printf '0.10.1\nactive\nusers=1\n1M\non\non\n--status--\npeers=1/2 lag=15m backlog=40 disk=ok free=9GiB sessions=2 push=3/0 turn=0 rejected=0\n! peer n2 lag 15m (40 records)\n--netlog--\n'
STUB
if out=$(OTTER_NODE_BIN="$work/stub/node-ok" PATH="$work/stub:$PATH" deploy/status.sh 2>&1); then fail "status must fail on a problem: $out"; fi
grep -q '^  n1  peers=1/2 lag=15m' <<< "$out" || fail "status health line: $out"
grep -q '^  n1  ! peer n2 lag 15m (40 records)$' <<< "$out" || fail "status problem line: $out"
grep -qE '^n1 .* on +on$' <<< "$out" || fail "status row with health block: $out"
grep -q '^health (otter-node status' <<< "$out" || fail "status health header: $out"
# healthy: exit 0
cat > "$work/stub/ssh" <<'STUB'
#!/bin/sh
printf '0.10.1\nactive\nusers=1\n1M\non\non\n--status--\npeers=2/2 lag=0s backlog=0 disk=ok free=9GiB sessions=2 push=3/0 turn=0 rejected=0\n--netlog--\n'
STUB
out=$(OTTER_NODE_BIN="$work/stub/node-ok" PATH="$work/stub:$PATH" deploy/status.sh 2>&1) || fail "healthy status failed: $out"
grep -q '^  n1  peers=2/2 lag=0s' <<< "$out" || fail "status healthy line: $out"
# a node below 0.10.1 (no status command, nothing between the markers, no TURN line): a note, not a failure
printf '#!/bin/sh\nprintf "0.10.0\\nactive\\nusers=1\\n1M\\non\\n--status--\\n--netlog--\\n"\n' > "$work/stub/ssh"
out=$(OTTER_NODE_BIN="$work/stub/node-ok" PATH="$work/stub:$PATH" deploy/status.sh 2>&1) || fail "old node failed the status run: $out"
grep -qE '^n1 .* 1M +on +-$' <<< "$out" || fail "old node row: $out"
grep -q '^  n1  - no health line: otter-node 0.10.0 has no status command (0.10.1+)$' <<< "$out" || fail "old node note: $out"
# a 0.10.1 node whose status is missing (status.json not written): a problem
printf '#!/bin/sh\nprintf "0.10.1\\nactive\\nusers=1\\n1M\\non\\non\\n--status--\\n--netlog--\\n"\n' > "$work/stub/ssh"
if out=$(OTTER_NODE_BIN="$work/stub/node-ok" PATH="$work/stub:$PATH" deploy/status.sh 2>&1); then fail "missing status passed: $out"; fi
grep -q '^  n1  ! no status from the running node' <<< "$out" || fail "missing status line: $out"

# --- harden-report.sh: read-only checks with stubbed system commands
hr="$work/hr"; hroot="$work/hroot"; mkdir -p "$hr" "$hroot/etc/otter" "$hroot/usr/local/bin" "$hroot/var/lib/otter"
cat > "$hr/sshd" <<'STUB'
#!/bin/sh
printf 'passwordauthentication yes\nkbdinteractiveauthentication no\npermitrootlogin prohibit-password\npubkeyauthentication yes\nx11forwarding no\nmaxauthtries 6\n'
STUB
cat > "$hr/ss" <<'STUB'
#!/bin/sh
printf 'tcp LISTEN 0 4096 0.0.0.0:27443 0.0.0.0:* users:(("otter-node",pid=10,fd=7))\ntcp LISTEN 0 4096 127.0.0.1:9477 0.0.0.0:* users:(("otter-node",pid=10,fd=9))\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\ntcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=1,fd=4))\ntcp LISTEN 0 511 0.0.0.0:8080 0.0.0.0:* users:(("someapp",pid=20,fd=5))\nudp UNCONN 0 0 127.0.0.53%%lo:53 0.0.0.0:* users:(("resolver",pid=30,fd=1))\nudp UNCONN 0 0 [::]:3478 [::]:* users:(("otter-node",pid=10,fd=11))\n'
STUB
cat > "$hr/systemd-analyze" <<'STUB'
#!/bin/sh
echo "$*" >> "$HR_LOG"
echo "→ Overall exposure level for otter-node.service: 1.5 OK"
STUB
printf '#!/bin/sh\necho "install ok installed"\n' > "$hr/dpkg-query"
printf '#!/bin/sh\necho '"'"'APT::Periodic::Unattended-Upgrade "1";'"'"'\n' > "$hr/apt-config"
# systemctl and ufw log every call: the report may only ask for state
printf '#!/bin/sh\necho "systemctl $*" >> "$HR_LOG"\ncase "$*" in *is-enabled*) echo enabled;; *) exit 0;; esac\n' > "$hr/systemctl"
printf '#!/bin/sh\necho "ufw $*" >> "$HR_LOG"\necho "Status: active"\n' > "$hr/ufw"
printf '#!/bin/sh\necho yes\n' > "$hr/timedatectl"
printf '#!/bin/sh\necho "otter:x:999:999::/var/lib/otter:/usr/sbin/nologin"\n' > "$hr/getent"
printf '#!/bin/sh\necho otter\n' > "$hr/id"
chmod +x "$hr/"*
echo key > "$hroot/etc/otter/node.key"; chmod 0644 "$hroot/etc/otter/node.key"   # owned by the test user, world-readable
chmod 0700 "$hroot/var/lib/otter"
before=$(cd "$hroot" && find . -printf '%p %m %s %T@\n' | sort)
hrun() { HR_LOG="$work/hr.log" PATH="$hr:$PATH" HARDEN_ROOT="$hroot" bash deploy/bundle/harden-report.sh 2>&1 || true; }
rm -f "$work/hr.log"; out=$(hrun)
grep -q '^FAIL ssh-password: PasswordAuthentication yes$' <<< "$out" || fail "harden ssh: $out"
grep -q '^PASS ssh-root: prohibit-password$' <<< "$out" || fail "harden root: $out"
grep -q '^PASS ssh-tries: 6$' <<< "$out" || fail "harden tries: $out"
grep -q '^PASS updates: unattended-upgrades on$' <<< "$out" || fail "harden updates: $out"
grep -q '^PASS firewall: ufw active$' <<< "$out" || fail "harden firewall: $out"
grep -qF 'WARN listener: 0.0.0.0:8080 (someapp, tcp)' <<< "$out" || fail "harden listener: $out"
if grep -q 'listener: .*:27443\|listener: .*:22 \|listener: .*:3478\|listener: .*:53 ' <<< "$out"; then fail "otter/sshd/loopback listener flagged: $out"; fi
[[ "$(grep -c '^WARN listener' <<< "$out")" == 1 ]] || fail "harden listeners: $out"
grep -q '^PASS metrics: 127.0.0.1:9477$' <<< "$out" || fail "harden metrics: $out"
grep -q '^PASS sandbox: exposure 1.5$' <<< "$out" || fail "harden sandbox: $out"
if grep -q 'sandbox-backup' <<< "$out"; then fail "backup unit checked though not installed: $out"; fi
grep -q '^PASS otter-user: no shell, no admin groups$' <<< "$out" || fail "harden user: $out"
grep -q "^FAIL file: $hroot/etc/otter/node.key is 644 " <<< "$out" || fail "harden key file: $out"
grep -q "^WARN data-dir: $hroot/var/lib/otter is [a-z]* 700 (want otter 700)$" <<< "$out" || fail "harden data dir: $out"
grep -q '^PASS clock: NTP synchronized$' <<< "$out" || fail "harden clock: $out"
if grep -vE '^(PASS|WARN|FAIL) [a-z0-9-]+: ' <<< "$out"; then fail "harden lines must be PASS|WARN|FAIL check: detail"; fi
# metrics on a public address is a FAIL; an exposed backup unit and a sudoers entry for otter are reported
cat > "$hr/ss" <<'STUB'
#!/bin/sh
printf 'tcp LISTEN 0 4096 0.0.0.0:9477 0.0.0.0:* users:(("otter-node",pid=10,fd=9))\n'
STUB
mkdir -p "$hroot/etc/systemd/system" "$hroot/etc/sudoers.d"; echo unit > "$hroot/etc/systemd/system/otter-backup.service"
echo 'otter ALL=(ALL) NOPASSWD: ALL' > "$hroot/etc/sudoers.d/x"
before=$(cd "$hroot" && find . -printf '%p %m %s %T@\n' | sort)
rm -f "$work/hr.log"; out=$(hrun)
grep -q '^FAIL metrics: /metrics listens on 0.0.0.0:9477$' <<< "$out" || fail "harden public metrics: $out"
grep -q '^WARN sandbox-backup: systemd-analyze security not available for otter-backup.service$' <<< "$out" || fail "harden backup unit: $out"
grep -q '^FAIL otter-user: .*listed in sudoers' <<< "$out" || fail "harden sudoers: $out"
# read-only, as executed: nothing under the root changed, systemctl/ufw/systemd-analyze were only asked for state
[[ "$(cd "$hroot" && find . -printf '%p %m %s %T@\n' | sort)" == "$before" ]] || fail "harden-report changed files"
if grep -vE '^(systemctl is-enabled [a-z.-]+|ufw status|security otter-(node|backup)\.service --no-pager)$' "$work/hr.log"; then
  fail "harden-report ran a changing command"
fi
# read-only, as written: no command in the report changes the host (redirections to /dev/null removed first)
if sed -E 's#[0-9&]*>[[:space:]]*/dev/null##g' deploy/bundle/harden-report.sh | grep -nE '(^|[;&|(`]|\$\()[[:space:]]*(rm|rmdir|chmod|chown|chgrp|mv|cp|ln|tee|touch|mkdir|truncate|dd|install|apt|apt-get|dpkg|dpkg-reconfigure|useradd|usermod|userdel|passwd|kill|pkill|reboot|shutdown|sysctl|mount|crontab)( |$)|sed +-i|ufw +(allow|deny|enable|disable|reset|delete|reload|limit)|systemctl +(start|stop|restart|reload|enable|disable|mask|unmask|daemon-reload|kill|edit|set-property)|ss +-K|>[[:space:]]*[A-Za-z/$~"'"'"']'; then
  fail "harden-report.sh must not change the host"
fi

# --- harden-check.sh: one SSH call per node streams the repo's report (bash -s); FAIL lines fail the run
cat > "$work/stub/ssh" <<STUB
#!/bin/sh
echo "ssh \$*" >> "$work/ssh.log"
cat > "$work/hc.stdin"
printf 'PASS ssh-root: no\n%s\n' "\${HC_LINE:-PASS clock: NTP synchronized}"
STUB
deploy/hosts.sh set n2 root@n2.example 2222 >/dev/null
rm -f "$work/ssh.log"
out=$(PATH="$work/stub:$PATH" deploy/harden-check.sh n1 2>&1) || fail "harden-check without FAIL: $out"
grep -q '^== n1$' <<< "$out" && grep -q '^  PASS ssh-root: no$' <<< "$out" || fail "harden-check table: $out"
[[ "$(wc -l < "$work/ssh.log")" == 1 ]] && grep -q 'root@n1.example bash -s$' "$work/ssh.log" || fail "harden-check ssh: $(cat "$work/ssh.log")"
cmp -s "$work/hc.stdin" deploy/bundle/harden-report.sh || fail "harden-check did not stream harden-report.sh"
rm -f "$work/ssh.log"
if out=$(HC_LINE='FAIL ssh-password: PasswordAuthentication yes' PATH="$work/stub:$PATH" deploy/harden-check.sh 2>&1); then
  fail "harden-check must fail on FAIL: $out"
fi
grep -q '^== n1$' <<< "$out" && grep -q '^== n2$' <<< "$out" || fail "harden-check all nodes: $out"
[[ "$(wc -l < "$work/ssh.log")" == 2 ]] || fail "harden-check one call per node: $(cat "$work/ssh.log")"
grep -q 'ssh -p 2222 .*root@n2.example bash -s$' "$work/ssh.log" || fail "harden-check port: $(cat "$work/ssh.log")"
if out=$(PATH="$work/stub:$PATH" deploy/harden-check.sh nope 2>&1); then fail "harden-check unknown label: $out"; fi
grep -q 'no SSH target' <<< "$out" || fail "harden-check unknown label message: $out"
echo "scripts test: ok"
