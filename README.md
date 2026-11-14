# otter-server

The OtterMSG node and admin tooling (Go module `ottermsg/server`). It owns the shared protobuf schemas in `proto/` and the cross-language test vectors in `testdata/vectors/`. Run `make gen` to regenerate protobuf code (via buf), `make check` to vet and test, and `make build` to build the binaries into `bin/`. Design and protocol specs are in [otter-docs](https://github.com/Shuttle25/otter-docs) (checked out next to this repo as `../docs`).

## Local development

`scripts/dev-node.sh` runs one development node with a plain `ws://` endpoint at `10.0.2.2:8080` (the Android emulator's alias for this machine). On the first run it creates a network in `.dev/` (gitignored), imports the signed manifest and a bootstrap invite, and prints the invite link and a QR code; **later runs reuse that network**, so apps that already joined keep working. Ctrl-C stops the node.

- `--host 192.168.x.y` advertises your PC's LAN IP instead, for a real phone on the same Wi-Fi (only when the network is created).
- `--reset` creates a new network. Apps that joined the old one must be reinstalled (or have their data cleared) and join again, so it asks for confirmation; `--yes` skips the prompt. `--keep` is accepted and ignored.

`scripts/dev-mesh.sh` does the same for three replicating nodes `a`, `b`, `c` on ports 8081–8083 (`.dev-mesh/`, logs in `.dev-mesh/<n>.log`), started in the background: `scripts/dev-mesh.sh stop` stops them, `kill b` / `start b` stops or starts one node for failover testing.

After changing nodes, sign and push the new manifest to the running nodes:

```
bin/otter-admin --dir .dev-mesh/admin manifest sign
bin/otter-admin --dir .dev-mesh/admin manifest publish --allow-plain
```

These setups are for development only: traffic is unencrypted and the admin passphrase is fixed. Production nodes use WSS on port 27443 with self-signed certificates pinned in the manifest.

## Releases and deployment

```
make release VERSION=0.2.0                         # dist/otter-node_0.2.0_linux_{amd64,arm64}, otter-admin, SHA256SUMS
deploy/push.sh fi-1 root@203.0.113.10              # bundle → install → checks
deploy/check.sh fi-1 root@203.0.113.10             # PASS/FAIL table
deploy/upgrade.sh root@203.0.113.10 dist/otter-node_0.2.1_linux_amd64   # automatic rollback (exit 2)
```

Node operator commands: `otter-node check --config F` (before start), `otter-node backup --config F --out FILE`
(consistent copy while running), `otter-node probe --url wss://H:P/path --pin B64` (pinned hello). Admin:
`otter-admin dns records|check`, `node set-ip|rotate-tls|drop-old-pins|env`. The step-by-step procedure is in the
project docs (`docs/11-deployment.md`); [`deploy/README.md`](deploy/README.md) is the one-screen reference.

Tests: `deploy/test/bundle_test.sh` (offline) and `deploy/test/e2e.sh [--keep]` (disposable Debian 12 VM under
QEMU/KVM: install, upgrade, rollback, backup, uninstall).

## Photos (blobs)

Members' photos travel as encrypted blobs: `blob.create` (signed `BLOB_META`), `blob.put`/`blob.get` in 256 KiB chunks,
`blob.ack` (`BLOB_FETCHED`). Chunk files live in `<data_dir>/blobs/` until every reader has fetched the blob (or it
expires) and are not backed up. Tuning in `node.toml`: `[limits] user_quota`, `max_blob`; `[replication] blob_bandwidth`.

## Password backups

A member's backup is a persistent blob (`BlobMeta.persistent`, at most 3 live per member, counted in `user_quota`) plus a
signed `BACKUP_META` (`backup.publish`); both replicate to every node and the newest version wins. A phone with only
a username and password restores through the public methods `backup.auth` (salt and KDF parameters; a stable fake salt
for unknown names) and `backup.fetch` (checks `SHA-256(auth_secret)`, grants `blob.get` on that one blob). Wrong guesses
are limited to 5 per username per hour and 20 per day per node. A newer install of a device (`PreKeys.installed_ms`)
cuts the old one off. Nothing to configure.

## Push

Optional FCM wake-ups (M5). A node pushes only when `/etc/otter/fcm.json` (a Firebase service-account key) exists;
`node.toml` always names it under `[push] fcm_credentials`, and a missing file means push is off (`push off` in the
log). When an urgent envelope is stored for a recipient with no session on the node, the responsible node (the one that
accepted it from the phone if it can push, else the first `push_capable` node in manifest order; D58) sends one constant, content-free push
(`"data": {"w": "1"}`, collapse key `otter`), at most one per device per 10 s. Phones register their token with a
signed `PUSH_TOKEN` (`push.register`); the newest per device wins. Code: `internal/push`, `internal/service/push.go`.

Enable it per node with `deploy/push-key.sh LABEL KEY` (streams the key over SSH, restarts, expects `push on`), then
`otter-admin node set-push --label LABEL`, `manifest sign`, `manifest publish`; `deploy/status.sh` shows a PUSH
column. The node must already run a release with M5. Step by step: [`deploy/FIRST-DEPLOY.md`](deploy/FIRST-DEPLOY.md)
("Push notifications"); quick reference: [`deploy/README.md`](deploy/README.md); creating the Firebase project:
`otter-android/README.md` ("Push / Firebase"). The key never goes into git, bundles or the admin dir.

## News (M6.5)

Otter news are announcements from the owner to every member, shown as messages from «Выдра» in the chat «Новости
Выдры». They are `ANNOUNCEMENT` records signed by a **news key** listed in the manifest (`news_keys`); the key lives in
the owner's desktop keyring, not in the admin dir. They are signed, **not** end-to-end encrypted: release notes only.
`otter-admin news init`, `manifest sign`, `manifest publish`, then `otter-admin announce --ru ru.txt --en en.txt`
(`--list`, `--delete ID`, `news revoke --pub HEX`). An announcement can carry an update: `deploy/release-apk.sh
VERSION APK` copies a release-signed APK to every node (`otter-node apk import`) and opens the news dialog; phones
download it with `apk.get` and check its SHA-256. Code: `internal/records` (validation), `internal/store` (news,
`news_deleted`), `internal/service/news.go`, `internal/apk`, `cmd/otter-admin`. Reference:
[`deploy/README.md`](deploy/README.md) ("News"); decisions D64–D69.

## REALITY and dial-out-only nodes (M7)

For members inside a censored network (Russia): phones there use a domestic node marked **`dial_out_only`** in the
manifest (`add-node.sh` asks, or `otter-admin node set-dial-out-only`): it dials the foreign nodes and is never
dialed by them. Foreign nodes get a **VLESS+REALITY** listener on :443 for peers only (embedded Xray-core, built with
just the needed features); probes without the key see the camouflage site, peers run the usual node handshake inside.
`deploy/reality-setup.sh LABEL --dest dl.google.com` sets it up on a 0.7.0+ node (`otter-node reality-check`
first: the site needs TLS 1.3, h2 and handshake records ≤ 8 KB), then `manifest sign` + `publish`. Peers try endpoints
in ranked order (REALITY, WSS fallback) and demote a throttled one; every outcome goes into the merged 200-line
connectivity log (`otter-node netlog`, last 5 lines in `deploy/status.sh`). Code: `internal/reality`,
`internal/netlog`, `internal/replication/endpoints.go`. Reference: [`deploy/README.md`](deploy/README.md)
("REALITY and dial-out-only nodes"); decisions D70–D75; checklist [`docs/m7-manual-test.md`](docs/m7-manual-test.md).

## Calls (TURN, M8)

1:1 audio calls: phones signal through the ordinary encrypted mailbox (`Content.call`, urgent, 2-minute record
expiry; nodes skip and purge expired envelopes) and send media (WebRTC, DTLS-SRTP end to end) through a **TURN relay
embedded in `otter-node`** (Pion `turn/v5` v5.1.3, `internal/turnsrv`). Each phone uses the relay of its own node:
`turn.credentials` (logged in) returns 12-hour TURN-REST credentials for this node only; phones ask on every call.
Ports **UDP 3478, TCP 3478, TLS 5349** (only when `[wss]` has TLS), relays on **UDP 49160–49200**, IPv4 only. Limits:
12 allocations per user, the port range per node, 200 kbit/s per allocation (`relay_kbps`); peers in private,
loopback, link-local, CGNAT, NAT64, 6to4, Teredo and similar ranges are refused, and the node's own addresses only
for its relay ports. The optional `[turn]` section needs the 0.8.0 binary; the per-node secret
`/etc/otter/turn.secret` comes from `otter-node turn keygen` and never leaves the node. `deploy/turn-setup.sh LABEL`
turns it on (`upgrade-all.sh` runs it for 0.8.0+, `--no-turn` skips); ufw only on an explicit yes, the cloud
firewall by hand. `deploy/status.sh` shows a TURN column, `otter-node stats` adds `turn_allocs=` /
`turn_relayed_bytes=`, `otter-node netlog` has the classes `auth`, `quota`, `listen`. `push.status` tells a caller
whether the callee has a push token. Reference: [`deploy/README.md`](deploy/README.md) ("Calls (TURN, M8, D77)");
decisions D76–D81; checklist [`docs/m8-manual-test.md`](docs/m8-manual-test.md).

## Private files (never commit)

| File | Where it lives | Why it is private |
|------|----------------|-------------------|
| `~/.otter-admin/` | admin PC only (outside the repo) | network admin key, node keys, TLS keys |
| `otter-server/.dev-mesh/`, `.vm/`, `dist/` | ignored | throwaway dev keys, build output with bundles |
| `/etc/otter/fcm.json` | push-capable servers only (`deploy/push-key.sh`) | Firebase service-account key |
| `local.properties`, `*.jks`, `keystore.properties` | owner's PC only | SDK path, release signing key |

`scripts/secrets-check.sh` (gitleaks v8.24.0 + personal-data grep) must pass before publishing.
