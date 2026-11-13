# M8 manual test (embedded TURN relay, call RPCs)

Local rows ran on 2026-11-13 on the development PC (no root on the PC, nothing installed, the regular `.dev-mesh/`
a/b/c left alone). Phone-side rows are in `otter-android/docs/m8-manual-test.md`. "—" = not run yet: needs `eeee`, the
ru-1 node, the two phones, or root on the PC (owner).

## Automated checks

```bash
export PATH=/usr/lib/go-1.26/bin:$HOME/go/bin:$PATH
make check                                              # vet + go test -race
go test ./internal/meshsim/ -run 'Turn|CallRelay' -count=3 -race -v
# scripts_test writes into dist/: run it in a copy of the tree
T=$(mktemp -d); git ls-files -z | xargs -0 tar -c | tar -x -C "$T"; (cd "$T" && bash deploy/test/scripts_test.sh)
CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$T/otter-node-amd64" ./cmd/otter-node
CGO_ENABLED=0 GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o "$T/otter-node-arm64" ./cmd/otter-node
ls -l "$T"/otter-node-*
```

## Local two-node run (`x`, `y` with TURN)

A throwaway network in its own directory (not `.dev-mesh/`). Both nodes are plain WSS on the PC's LAN address
(`192.168.x.y`, reachable from the emulators and from the other node — `10.0.2.2` only works inside an emulator, so
nodes advertising it cannot replicate). TURN: `x` on UDP/TCP 3478, `y` on UDP/TCP 3479, `relay_ip` = the LAN address,
**one shared relay port range 49160–49200 for both nodes** (on one host a relay only reaches the other node's relay
ports if they are inside its own range — on real nodes the other relay has another IP), `allow_private_peers = true`.
Plain nodes have no TLS certificate, so TURN over TLS (5349) is not exercised locally (meshsim covers it).

```bash
cd otter-server && make build
D=/tmp/otter-m8; rm -rf $D; mkdir -p $D; LAN=192.168.x.y      # this PC's address
export OTTER_ADMIN_PASSPHRASE=dev-only-passphrase      # throwaway network only
admin="bin/otter-admin --dir $D/admin"; node=bin/otter-node
$admin network init
$admin node add --label x --plain --wss-host $LAN --wss-port 9381
$admin node add --label y --plain --wss-host $LAN --wss-port 9382
$admin manifest sign
# per node: data_dir, node_key, network_pub, manifest_file, [wss] listen 0.0.0.0:938N + path, [mesh] allow_plain, and
#   [turn] enabled = true, udp_listen = ":347N", tcp_listen = ":347N", relay_ip = "$LAN",
#          relay_port_min = 49160, relay_port_max = 49200, max_allocations = 20,
#          secret_file = "$D/turn-N.secret", allow_private_peers = true
$node turn keygen --config $D/x.toml; $node turn keygen --config $D/y.toml
$node check --config $D/x.toml | grep turn            # ok turn secret … (32 bytes), relay 192.168.x.y:49160-49200
for n in x y; do $node import --config $D/$n.toml $D/admin/manifest.bin; nohup $node run --config $D/$n.toml >> $D/$n.log 2>&1 & done
$node stats --config $D/x.toml                         # … turn_allocs=N turn_relayed_bytes=M (snapshot < 60 s old)
cat $D/data-x/turn.stats.json
```

"UDP blocked" and "phone pinned to a node" were done **inside the emulators** (`adb root`; Google APIs images allow it):
`iptables -A OUTPUT -p udp -d $LAN -j DROP` and `iptables -A OUTPUT -p tcp -d $LAN --dport 9382 -j REJECT` — no rule
on the PC. "TURN off": the node restarted without `[turn]`.

## Rows

| # | Step | Expected | Result |
|---|------|----------|--------|
| 1 | `make check` | all green | PASS 2026-11-13 |
| 2 | meshsim `-run 'Turn\|CallRelay' -count=3 -race` | 3 × 3 tests pass | PASS 2026-11-13 (`TestCallRelayAcrossNodes` UDP/TCP/TLS, `TestTurnCredentialsAreNodeLocal`, `TestTurnOffNode`) |
| 3 | `deploy/test/scripts_test.sh` (copy of the tree) | `scripts test: ok` | PASS 2026-11-13 (also `bundle_test.sh`: 0.8.0 bundle with `[turn]`, real `turn keygen` + `check`) |
| 4 | `otter-node` size, `-s -w`, linux | recorded | 2026-11-13: amd64 20 037 794 B (0.7.0: 19 558 562, +0.48 MB), arm64 18 612 386 B (0.7.0: 18 219 170, +0.39 MB) |
| 5 | `turn keygen` twice; `--force`; `check` | second run refused; secret 32 bytes, 0640, never printed; `check` line `ok turn secret …` | PASS 2026-11-13 |
| 6 | Start `x`, `y` | `"turn on"` log line with udp/tcp/relay/ports; listeners on 3478/3479 | PASS 2026-11-13 |
| 7 | Two phones on one node (`y`) talk | 4 allocations on `y`, relayed bytes grow, allocations back to 0 after hang-up | PASS 2026-11-13: 2:55 call, 353 036 B relayed, `allocations 0` afterwards |
| 8 | Phone A on `x`, phone B on `y` (cross-node relay) | 2 allocations on each node, bytes on both | PASS 2026-11-13: `x` 66 182 B, `y` +65 250 B in a 0:55 call; both back to 0 |
| 9 | UDP to the TURN ports blocked (inside the emulators) | call connects over TCP to the relay | PASS 2026-11-13: phones log `call:relay-tcp`; TCP sessions on 3478/3479 |
| 10 | Node without `[turn]` | `turn.credentials` → UNAVAILABLE; phone shows «Звонки недоступны: сервер не обновлён» | PASS 2026-11-13 after app fixes `dc98cce` (credentials asked per call) and `c05ab41` (notice reached the screen) |
| 11 | Audio is encrypted on the relay: `sudo tcpdump -i any -n -X udp portrange 49160-49200` during a call | only DTLS/SRTP (`17 fe fd` DTLS records, then random-looking RTP payloads), no readable audio | — (needs root on the PC; owner) |
| 12 | Firewall | no temporary rule left on the PC | PASS: none was added (rules only inside the emulators) |
| 13 | (owner) `deploy/upgrade-all.sh 0.8.0` | both nodes 0.8.0, `turn-setup.sh --if-missing` enables TURN, summary `TURN ok` | — |
| 14 | (owner) cloud firewalls: UDP 3478, TCP 3478, TCP 5349, UDP 49160–49200 on `eeee` and ru-1 | open | — |
| 15 | (owner) `deploy/status.sh` | `TURN on` on both nodes; stats line has `turn_allocs=` | — |
| 16 | (owner) a phone without a valid session asks for credentials (e.g. `otter-node` test client not logged in) | UNAUTHORIZED | — (covered by `TestTurnCredentialsAndPushStatus`; on the real network optional) |
| 17 | (owner) during a real call: `ssh root@eeee 'runuser -u otter -- otter-node stats --config /etc/otter/node.toml'` | `turn_allocs` > 0, relayed bytes grow | — |
| 18 | (owner) `ssh root@eeee 'tcpdump -n -X -c 50 udp portrange 49160-49200'` during a call | only DTLS/SRTP | — |

## Findings

* `push.status` answers `has_push=true` whenever the node holds a PUSH_TOKEN, even if no node can push (the local
  nodes have no FCM key). On the real network `eeee` pushes, so this only matters for test networks.
* The phone's connection closes a few seconds after the app leaves the screen when push cannot wake it. On the local
  network (no FCM key) a locked phone therefore rang only when the call came within that grace time; the offer then
  sat in the node's mailbox and became a «Пропущенный звонок» when the app opened (correct stale-offer rule). Real
  ringing of a locked phone with the app closed needs FCM: phone checklist row 6.
