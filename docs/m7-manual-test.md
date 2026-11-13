# M7 manual test (REALITY, dial-out-only, connectivity log)

Local rows ran on 2026-11-13 on the development PC (no root, nothing installed, the regular `.dev-mesh/` a/b/c left
alone). Phone-side rows are in `otter-android/docs/m7-manual-test.md`. "—" = not run yet: needs `eeee`, the ru-1
node in Russia, the two phones or the Russian mobile networks (owner).

## Automated checks

```bash
export PATH=/usr/lib/go-1.26/bin:$HOME/go/bin:$PATH
make check                                              # vet + go test -race
go test ./... -count=1
go test ./internal/meshsim/ -run Reality -count=3 -v
# scripts_test writes into dist/: run it in a copy of the tree
T=$(mktemp -d); git ls-files -z | xargs -0 tar -c | tar -x -C "$T"; (cd "$T" && bash deploy/test/scripts_test.sh)
CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$T/otter-node-amd64" ./cmd/otter-node
CGO_ENABLED=0 GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o "$T/otter-node-arm64" ./cmd/otter-node
ls -l "$T"/otter-node-*
```

## Local two-node run (`fi` with REALITY, `ru` dial-out-only)

A throwaway network in its own directory (not `.dev-mesh/`), ports 9181/9182/24443. WSS from `ru` to `fi` is
"blocked" without a firewall: the manifest gives `fi`'s ws endpoint the closed port 9191, while `fi` really listens on
9181. Only the emulator reaches it, through `adb reverse tcp:9191 tcp:9181`.

```bash
cd otter-server && make build
D=/tmp/otter-m7; rm -rf $D; mkdir -p $D
export OTTER_ADMIN_PASSPHRASE=dev-only-passphrase      # throwaway network only
admin="bin/otter-admin --dir $D/admin"; node=bin/otter-node
bin/otter-node reality-check dl.google.com www.apple.com www.microsoft.com   # pick one that says ok
$admin network init
$admin node add --label fi --plain --wss-host 127.0.0.1 --wss-port 9191
$admin node add --label ru --plain --wss-host 127.0.0.1 --wss-port 9182
$admin node set-dial-out-only --label ru
netpub=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["network_pub"])' $D/admin/network.json)
path_of() { python3 -c 'import json,sys
for x in json.load(open(sys.argv[1]))["nodes"]:
    if x["label"] == sys.argv[2]: print(x["endpoints"][0]["path"])' $D/admin/nodes.json "$1"; }
sid=$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n'); vless=$(cat /proc/sys/kernel/random/uuid)
cat > $D/fi.toml <<TOML
data_dir = "$D/data-fi"
node_key = "$D/admin/nodes/fi/node.key"
network_pub = "$netpub"
manifest_file = "$D/admin/manifest.bin"
log_level = "debug"
[wss]
listen = "127.0.0.1:9181"
path = "$(path_of fi)"
[mesh]
allow_plain = true
[reality]
listen = "127.0.0.1:24443"
private_key_file = "$D/fi-reality.key"
dest = "dl.google.com:443"
server_names = ["dl.google.com"]
short_ids = ["$sid"]
vless_uuid = "$vless"
TOML
cat > $D/ru.toml <<TOML
data_dir = "$D/data-ru"
node_key = "$D/admin/nodes/ru/node.key"
network_pub = "$netpub"
manifest_file = "$D/admin/manifest.bin"
log_level = "debug"
[wss]
listen = "127.0.0.1:9182"
path = "$(path_of ru)"
[mesh]
allow_plain = true
TOML
pub=$($node reality keygen --config $D/fi.toml | sed -n 's/.*public key: //p')
$admin node add-reality --label fi --host 127.0.0.1 --port 24443 --pub "$pub" --server-name dl.google.com \
  --short-id "$sid" --uuid "$vless"
$admin manifest sign && $admin node list
for n in fi ru; do $node import --config $D/$n.toml $D/admin/manifest.bin; done
out=$($admin invite bootstrap); echo "$out" | grep '^otter://' > $D/bootstrap-invite.txt
$node import --config $D/fi.toml "$(echo "$out" | sed -n 's/^Record: //p')"
for n in fi ru; do nohup $node run --config $D/$n.toml >> $D/$n.log 2>&1 & echo $! > $D/$n.pid; done
sleep 15
$node netlog --config $D/ru.toml; $node netlog --config $D/fi.toml
curl -vk --resolve dl.google.com:24443:127.0.0.1 https://dl.google.com:24443/ -o /dev/null 2>&1 | grep -E 'subject|issuer|HTTP/'
$node stats --config $D/ru.toml; $node stats --config $D/fi.toml      # same record counts = replicated
# stop: for n in fi ru; do kill -INT $(cat $D/$n.pid); done; rm -rf $D
```

Phones: emulator on `ru` = `adb reverse tcp:9182 tcp:9182` only; on `fi` = `adb reverse --remove tcp:9182;
adb reverse tcp:9191 tcp:9181` and restart the app. The second party on 2026-11-13 was a temporary JVM client (a copy
of `otter-android/core/data/src/test/.../LiveClient.kt` whose OkHttp socket factory maps port 9191 to 9181, not
committed) registered on `fi`; two emulators/phones work the same way.

## Rows

| # | Step | Expected | Result |
|---|------|----------|--------|
| 1 | `make check`; `go test ./... -count=1` | all green | PASS 2026-11-13 |
| 2 | meshsim `-run Reality -count=3` | 3 × 3 tests pass | PASS 2026-11-13 (REALITY carries replication when WS is censored, WS fallback when REALITY is censored, probe sees camouflage) |
| 3 | `deploy/test/scripts_test.sh` (in a copy of the tree) | `scripts test: ok` | PASS 2026-11-13 |
| 4 | `otter-node` size, `-s -w`, linux | recorded | 2026-11-13: amd64 19 558 562 B (0.6.0: 14 233 762, +5.3 MB), arm64 18 219 170 B (0.6.0: 13 369 506, +4.8 MB) |
| 5 | `reality-check dl.google.com www.apple.com www.microsoft.com` | sites REALITY can mirror say `ok`, others `FAIL` | PASS 2026-11-13 after fix `ecd3858`: `ok dl.google.com`, `ok www.apple.com`, `FAIL www.microsoft.com … REALITY handshake through it failed (handshake records over 8 KB?)`. Before the fix microsoft said `ok` but no peer could authenticate through it (8273-byte certificate record; the REALITY library gives up above 8192) |
| 6 | `node add-reality` on a `--plain` dev node | REALITY endpoint with the ws path | PASS 2026-11-13 after fix `44b7a40` (before: «no WSS endpoint to take the secret path from») |
| 7 | Start `fi` + `ru`; `netlog` on `ru` | ws to `fi` `fail refused`, then `reality … out ok` | PASS 2026-11-13: `fi ws_plain:127.0.0.1:9191 out fail refused ×1`, `fi reality:127.0.0.1:24443 out ok ×2` (two dials raced at start; duplicate-session handling kept one, no flap afterwards) |
| 8 | `netlog` on `fi` | `ru reality in ok`; `fi` never dials `ru` (dial-out-only) | PASS 2026-11-13: `ru reality in ok ×2`, no outbound line |
| 9 | `curl -vk --resolve dl.google.com:24443:127.0.0.1 https://dl.google.com:24443/` | camouflage site's real certificate, h2 | PASS 2026-11-13: TLS 1.3, h2, `CN=*.google.com`, issuer Google Trust Services WE2, `HTTP/2 302` |
| 10 | Messages phone(`ru`) ↔ client(`fi`) both ways; `stats` on both | delivered + read; same record counts | PASS 2026-11-13 (see android rows 3–6); `users=2 records=29 oplog_seq=47` on both |
| 11 | Firewall | no temporary rule left | PASS: no rule was added (closed-port method; no root on the PC) |
| 12 | (owner) `deploy/upgrade-all.sh 0.7.0`; `deploy/status.sh` | `eeee` and the ru-1 node on 0.7.0, netlog lines shown | — |
| 13 | (owner) `ssh root@eeee /usr/local/bin/otter-node reality-check dl.google.com www.apple.com …` | at least one `ok` from `eeee` | — |
| 14 | (owner) `deploy/reality-setup.sh eeee --dest <ok site>`; `manifest sign` + `publish`; cloud firewall :443 | `"reality on"`, manifest has the REALITY endpoint | — |
| 15 | (owner) ru-1 node `dial_out_only` (`add-node.sh … --dial-out-only` or `node set-dial-out-only`) | `node list` shows `dial_out_only=true`; `eeee` never dials it | — |
| 16 | (owner) block direct WSS ru-1 → `eeee` (or wait for real throttling); `netlog` on both | ru-1: `reality:… out ok`; `eeee`: `<itsoft> reality in ok` | — |
| 17 | (owner) a non-Otter probe of `eeee:443` from outside: `curl -vk --resolve <site>:443:<eeee ip> https://<site>/` | the camouflage site's certificate | — |
| 18 | (owner) a week of normal use; `deploy/status.sh` | no `reset_after_kb` storms; demoted endpoints recover after 24 h | — |
