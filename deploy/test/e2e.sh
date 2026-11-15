#!/usr/bin/env bash
# Deploy end-to-end test against a disposable VM. Usage: e2e.sh [--keep]
set -euo pipefail
cd "$(dirname "$0")/../.."
keep=0; if [[ "${1:-}" == --keep ]]; then keep=1; fi
work=$(mktemp -d)
cleanup() { if (( ! keep )); then deploy/test/vm.sh stop; fi; rm -rf "$work"; }
trap cleanup EXIT
step() { printf '\n######## %s\n' "$*"; }
fail() { printf '\ne2e: FAIL: %s\n' "$*" >&2; exit 1; }
export OTTER_ADMIN_DIR="$work/admin" OTTER_ADMIN_PASSPHRASE=e2e-only-passphrase
export OTTER_SSH_PORT=2222 OTTER_SSH_OPTS="-i $PWD/.vm/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
T=root@127.0.0.1
vmsh() { deploy/test/vm.sh ssh "$@"; }

step "build"
make -s build
make -s release VERSION=0.0.1-e2e >/dev/null
make -s release VERSION=0.0.2-e2e >/dev/null
step "VM"
deploy/test/vm.sh start
step "network"
bin/otter-admin --dir "$OTTER_ADMIN_DIR" network init >/dev/null
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node add --label vm --wss-host 127.0.0.1 --ip 127.0.0.1
bin/otter-admin --dir "$OTTER_ADMIN_DIR" manifest sign >/dev/null
inv=$(bin/otter-admin --dir "$OTTER_ADMIN_DIR" invite bootstrap)
link=$(grep -m1 '^otter://' <<< "$inv")
step "install (push.sh)"
deploy/make-bundle.sh vm 0.0.1-e2e
deploy/push.sh vm "$T"
[[ "$(vmsh /usr/local/bin/otter-node version)" == 0.0.1-e2e ]] || fail "installed version"
step "root deploy steps never follow the node user's links (C3, D82)"
if vmsh /usr/local/bin/otter-node apk import --config /etc/otter/node.toml /etc/hostname; then fail "apk import ran as root"; fi
vmsh 'runuser -u otter -- sh -c "rm -rf /var/lib/otter/apk && ln -s /etc /var/lib/otter/apk"'
if printf 'apk' | vmsh 'runuser -u otter -- /usr/local/bin/otter-node apk import --config /etc/otter/node.toml -'; then
  fail "otter wrote an APK into /etc"
fi
vmsh 'runuser -u otter -- sh -c "mv /var/lib/otter/site /var/lib/otter/site.real && ln -s /etc /var/lib/otter/site"'
deploy/make-bundle.sh vm 0.0.1-e2e >/dev/null
if deploy/push.sh vm "$T" >/dev/null 2>&1; then fail "install followed the planted site link"; fi
[[ "$(vmsh stat -c %U:%G /etc)" == root:root ]] || fail "/etc owner changed"
vmsh 'test -z "$(find /etc -maxdepth 1 -user otter)"' || fail "otter-owned files in /etc"
vmsh 'rm /var/lib/otter/apk /var/lib/otter/site && mv /var/lib/otter/site.real /var/lib/otter/site'
deploy/make-bundle.sh vm 0.0.1-e2e >/dev/null
deploy/push.sh vm "$T" >/dev/null || fail "re-install after cleanup"
[[ -z "$(ls "$OTTER_ADMIN_DIR"/invites/*.bin 2>/dev/null)" ]] || fail "bootstrap invite not moved to delivered/"
step "install again (idempotent)"
deploy/make-bundle.sh vm 0.0.1-e2e
deploy/push.sh vm "$T"
step "upgrade to 0.0.2-e2e"
deploy/upgrade.sh "$T" dist/otter-node_0.0.2-e2e_linux_amd64
[[ "$(vmsh /usr/local/bin/otter-node version)" == 0.0.2-e2e ]] || fail "upgraded version"
step "upgrade with a broken binary → rollback"
printf '#!/bin/sh\nexit 1\n' > "$work/broken"
set +e; deploy/upgrade.sh "$T" "$work/broken"; rc=$?; set -e
[[ $rc == 2 ]] || fail "expected exit 2 (rolled back), got $rc"
[[ "$(vmsh /usr/local/bin/otter-node version)" == 0.0.2-e2e ]] || fail "version after rollback"
vmsh test -x /usr/local/bin/otter-node.failed || fail "failed binary not kept"
OTTER_SKIP_DNS=1 deploy/check.sh vm "$T"
step "backups"
vmsh /usr/local/lib/otter/backup.sh --install
vmsh systemctl start otter-backup.service
vmsh 'ls /var/backups/otter/node-*.db' || fail "no daily backup"
if (( keep )); then
  rm -rf .vm/admin && cp -r "$OTTER_ADMIN_DIR" .vm/admin
  printf '\nVM kept running (admin dir copied to .vm/admin). Invite for LiveNodeTest:\n%s\nStop with deploy/test/vm.sh stop\n' "$link"
  printf '\ne2e: all steps passed (VM kept)\n'
  exit 0
fi
step "uninstall"
vmsh /usr/local/lib/otter/uninstall.sh
vmsh test -d /var/lib/otter || fail "data removed without --purge"
vmsh test ! -e /etc/otter || fail "/etc/otter left behind"
step "reinstall over kept data"
deploy/make-bundle.sh vm 0.0.2-e2e && deploy/push.sh vm "$T"
step "uninstall --purge"
vmsh /usr/local/lib/otter/uninstall.sh --purge
vmsh test ! -e /var/lib/otter || fail "purge left /var/lib/otter"
rm -f dist/*-e2e*
(cd dist && if ls otter-*_* >/dev/null 2>&1; then sha256sum otter-*_* > SHA256SUMS; else rm -f SHA256SUMS; fi)
printf '\ne2e: all steps passed\n'
