# otter-server

The OtterMSG node and admin tooling (Go module `ottermsg/server`). It owns the shared protobuf schemas in `proto/` and the cross-language test vectors in `testdata/vectors/`. Run `make gen` to regenerate protobuf code (via buf), `make check` to vet and test, and `make build` to build the binaries into `bin/`. Design and protocol specs are in [`../docs`](../docs).

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
