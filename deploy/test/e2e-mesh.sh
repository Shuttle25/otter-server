#!/usr/bin/env bash
# Two-node deploy test on two VMs: add-node, replication, upgrade-all, status, sandbox (D120). Usage: e2e-mesh.sh [--keep]
# Releases are 0.10.x-e2e so bundles carry [turn] and the 0.10.1 units, and upgrade-all runs turn-setup and sandbox-setup.
set -euo pipefail
cd "$(dirname "$0")/../.."
keep=0; if [[ "${1:-}" == --keep ]]; then keep=1; fi
work=$(mktemp -d)
vm() { local n=$1; shift; case $n in a) OTTER_VM=a OTTER_VM_SSH=2222 OTTER_VM_WSS=27443 deploy/test/vm.sh "$@" ;;
                                      b) OTTER_VM=b OTTER_VM_SSH=2223 OTTER_VM_WSS=27444 deploy/test/vm.sh "$@" ;; esac; }
# only files this test creates: never other bundle files, the owner's are in dist/ too
clean_dist() {
  rm -f dist/*-e2e* dist/bundle-a.* dist/bundle-b.*
  (cd dist 2>/dev/null && if ls otter-*_* >/dev/null 2>&1; then sha256sum otter-*_* > SHA256SUMS; else rm -f SHA256SUMS; fi) || true
}
cleanup() {
  if (( keep )); then
    rm -rf .vm/admin-mesh && cp -r "$OTTER_ADMIN_DIR" .vm/admin-mesh 2>/dev/null || true
    printf '\nVMs kept running (admin dir copied to .vm/admin-mesh). Stop with: OTTER_VM=a deploy/test/vm.sh stop; OTTER_VM=b deploy/test/vm.sh stop\n'
  else
    vm a stop || true; vm b stop || true
  fi
  clean_dist; rm -rf "$work"
}
trap cleanup EXIT
step() { printf '\n######## %s\n' "$*"; }
fail() { printf '\ne2e-mesh: FAIL: %s\n' "$*" >&2; exit 1; }
export OTTER_ADMIN_DIR="$work/admin" OTTER_ADMIN_PASSPHRASE=e2e-only-passphrase OTTER_SKIP_DNS=1
export OTTER_SSH_OPTS="-i $PWD/.vm/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
stat_of() { vm "$1" ssh runuser -u otter -- /usr/local/bin/otter-node stats --config /etc/otter/node.toml; }
records() { sed -E 's/.*records=([0-9]+).*/\1/' <<< "$1"; }
has_session() { vm "$1" ssh "journalctl -u otter-node --no-pager | grep -q 'peer session up'"; }
# Both nodes' manifest addresses are 127.0.0.1:<port>, which on the host is each VM's hostfwd.
# Inside VM $1, traffic to 127.0.0.1:$2 (the other node) is DNATed to the host (10.0.2.2 in QEMU
# user networking), whose hostfwd for port $2 reaches the other VM.
bridge() {
  vm "$1" ssh "set -e
    command -v nft >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables >/dev/null; }
    sysctl -qw net.ipv4.conf.all.route_localnet=1
    nft add table ip otterlab
    nft add chain ip otterlab out '{ type nat hook output priority -100; }'
    nft add rule ip otterlab out ip daddr 127.0.0.1 tcp dport $2 dnat to 10.0.2.2:$2
    nft add chain ip otterlab post '{ type nat hook postrouting priority 100; }'
    nft add rule ip otterlab post ip daddr 10.0.2.2 masquerade"
}

step "build"
make -s build
make -s release VERSION=0.10.1-e2e >/dev/null
step "VMs"
vm a start; vm b start
bridge a 27444; bridge b 27443
step "network + first node (add-node.sh)"
bin/otter-admin --dir "$OTTER_ADMIN_DIR" network init >/dev/null
# first node: registered and signed by hand because the bootstrap invite needs a signed manifest
# and must exist before a's bundle is built; add-node.sh then skips add/sign and installs it
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node add --label a --wss-host 127.0.0.1 --ip 127.0.0.1 >/dev/null
bin/otter-admin --dir "$OTTER_ADMIN_DIR" manifest sign >/dev/null
bin/otter-admin --dir "$OTTER_ADMIN_DIR" invite bootstrap >/dev/null
deploy/add-node.sh a root@127.0.0.1 --ip 127.0.0.1 --ssh-port 2222 --version 0.10.1-e2e
step "second node (add-node.sh)"
deploy/add-node.sh b root@127.0.0.1 --ip 127.0.0.1 --wss-port 27444 --ssh-port 2223 --version 0.10.1-e2e
[[ "$(deploy/hosts.sh get b)" == "root@127.0.0.1 2223" ]] || fail "host of b"
step "replication"
sa=$(stat_of a); sb=$(stat_of b)
for _ in $(seq 60); do
  sa=$(stat_of a); sb=$(stat_of b)
  if (( $(records "$sb") >= $(records "$sa") )) && has_session a && has_session b; then break; fi
  sleep 1
done
echo "a: $sa"; echo "b: $sb"
(( $(records "$sb") >= $(records "$sa") )) || fail "b did not catch up with a"
has_session a || fail "no peer session on a"
has_session b || fail "no peer session on b"
step "status"
deploy/status.sh || fail "status reported a problem"
step "upgrade-all to 0.10.2-e2e"
deploy/upgrade-all.sh 0.10.2-e2e
[[ "$(vm a ssh /usr/local/bin/otter-node version)" == 0.10.2-e2e ]] || fail "a version"
[[ "$(vm b ssh /usr/local/bin/otter-node version)" == 0.10.2-e2e ]] || fail "b version"
again=$(deploy/upgrade-all.sh 0.10.2-e2e); echo "$again"
[[ $(grep -c 'already 0.10.2-e2e' <<< "$again") == 2 ]] || fail "second run should skip both nodes"
deploy/status.sh || fail "status after upgrade"
step "sandbox: forced re-install with health check, score, TURN listeners, backup unit, harden report"
deploy/sandbox-setup.sh a || fail "sandbox-setup a (real systemd: daemon-reload, restart, health)"
for v in a b; do
  s=$(vm $v ssh "systemd-analyze security otter-node --no-pager | tail -n1")
  awk -v s="$(sed -nE 's/.*: ([0-9.]+) .*/\1/p' <<< "$s")" 'BEGIN { exit !(s != "" && s <= 2.0) }' || fail "$v sandbox: $s"
  vm $v ssh "ss -H -lun 'sport = :3478' | grep -q . && ss -H -ltn 'sport = :5349' | grep -q ." || fail "$v: TURN not listening under the sandbox"
  vm $v ssh "ss -H -ltn 'sport = :9477' | grep -q '127.0.0.1:9477'" || fail "$v: metrics not on loopback under the sandbox"
  # status.json written under UMask=0077 and read by the otter user; exit 2 (a peer problem) is not a sandbox failure
  vm $v ssh "runuser -u otter -- /usr/local/bin/otter-node status --config /etc/otter/node.toml --line; [ \$? -ne 1 ]" ||
    fail "$v: no status.json under the sandbox"
  vm $v ssh "systemctl start otter-backup.service && ls /var/backups/otter/node-*.db >/dev/null" || fail "$v: backup unit"
  # the report exits 1 on any FAIL (a test VM has no firewall or unattended-upgrades); only the sandbox line matters here
  report=$(vm $v ssh 'bash -s' < deploy/bundle/harden-report.sh || true); echo "$report"
  grep -q '^PASS sandbox' <<< "$report" || fail "$v: harden report"
done
printf '\ne2e-mesh: all steps passed\n'
