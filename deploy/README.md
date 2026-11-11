# deploy/ — quick reference

The full procedure (requirements, DNS, security checklist) is in the project docs: `docs/11-deployment.md`.
Every script prints its actions (`==> …`) and stops at the first error.
First real deployment step by step (what gets installed, every command): [FIRST-DEPLOY.md](FIRST-DEPLOY.md).

## Build

```bash
make build                      # bin/otter-admin, bin/otter-node for this machine (needed by the scripts)
make release VERSION=1.2.0      # dist/otter-node_1.2.0_linux_{amd64,arm64}, dist/otter-admin_…, dist/SHA256SUMS
```

## New node

```bash
bin/otter-admin network init                                   # once per network
bin/otter-admin node add --label fi-1 --wss-host chat.example.org --ip 203.0.113.10
bin/otter-admin manifest sign
bin/otter-admin dns records                                    # create these at the DNS provider
bin/otter-admin dns check --label fi-1                         # wait until ok (TTL 300)
bin/otter-admin invite bootstrap                               # first node of a new network only
deploy/push.sh fi-1 root@203.0.113.10                          # bundle → install → checks
```

`push.sh` builds `dist/bundle-<label>.tar.gz` (private keys, mode 0600) if missing and deletes it after a
successful install; pending bootstrap invites go into the bundle and move to `~/.otter-admin/invites/delivered/`.

## Day 2

| Task | Command |
|------|---------|
| Health checks | `deploy/check.sh fi-1 root@203.0.113.10` |
| Upgrade (auto rollback) | `deploy/upgrade.sh root@203.0.113.10 dist/otter-node_1.2.1_linux_amd64` (exit 0 ok, 2 rolled back, 3 manual) |
| New IP | `otter-admin node set-ip --label fi-1 --ip 198.51.100.7` → DNS → `push.sh` |
| Rotate TLS | `node rotate-tls` → `manifest sign` + `manifest publish` → apps update → `push.sh` → `node drop-old-pins` → `manifest sign` + `publish` |
| Daily DB backups | on the server: `/usr/local/lib/otter/backup.sh --install` |
| Uninstall | on the server: `/usr/local/lib/otter/uninstall.sh [--purge]` |

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `OTTER_ADMIN_DIR` | `~/.otter-admin` | admin state (network key, nodes, manifest) |
| `OTTER_ADMIN_PASSPHRASE` | prompt | admin key passphrase (tests only) |
| `OTTER_SSH_PORT` | `22` | SSH port of the servers |
| `OTTER_SSH_OPTS` | — | extra `ssh`/`scp` options, e.g. `-i ~/.ssh/otter` |
| `OTTER_PROBE_ADDR` | — | `check.sh`: connect probes to `host:port` instead of the node's hostname |
| `OTTER_SKIP_DNS` | `0` | `check.sh`: `1` skips the DNS check |

## Tests

```bash
deploy/test/bundle_test.sh      # offline: bundle contents and `otter-node check`
deploy/test/e2e.sh [--keep]     # disposable Debian 12 VM (QEMU/KVM): install, upgrade, rollback, backup, uninstall
```
