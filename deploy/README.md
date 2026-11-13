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

First node of a **new** network: follow [FIRST-DEPLOY.md](FIRST-DEPLOY.md). Every further node is one command:

```bash
deploy/add-node.sh fi-2 root@198.51.100.20 --ip 198.51.100.20 [--domain chat2.example.org]
```

Options: `--ip` (repeat for IPv6), `--domain`, `--wss-port P`, `--ssh-port N`, `--version V` (bundle that release).
It registers the node, signs the manifest if it doesn't list the node yet (asks for the admin passphrase), records
the SSH target in `~/.otter-admin/hosts`, waits for DNS when `--domain` is given, builds the bundle, runs `push.sh`
(install + checks) and publishes the manifest to the other running nodes, which connect to the new one without a
restart. Phones learn the node on their next connection. If it stops, fix the cause and re-run the same command:
finished steps are skipped.

`push.sh` builds `dist/bundle-<label>.tar.gz` (private keys, mode 0600) if missing and deletes it after a
successful install; pending bootstrap invites go into the bundle and move to `~/.otter-admin/invites/delivered/`.

## Day 2

| Task | Command |
|------|---------|
| Health checks | `deploy/check.sh fi-1 root@203.0.113.10` |
| Upgrade (auto rollback) | `deploy/upgrade.sh root@203.0.113.10 dist/otter-node_1.2.1_linux_amd64` (exit 0 ok, 2 rolled back, 3 manual) |
| All nodes at a glance | `deploy/status.sh` (target, version, hello, service, DB counts, disk, push; exit 1 on any problem) |
| Upgrade every node | `deploy/upgrade-all.sh 1.2.1 [--only fi-1] [--no-news]` (builds the release if missing, skips nodes already on it, stops at the first rollback; exit 0 / 2 rolled back / 3 manual; then offers the news dialog) |
| SSH target of a node | `deploy/hosts.sh set fi-1 root@203.0.113.10 [port]` / `get` / `list` / `rm` |
| New IP | `otter-admin node set-ip --label fi-1 --ip 198.51.100.7` → DNS → `push.sh` |
| Rotate TLS | `node rotate-tls` → `manifest sign` + `manifest publish` → apps update → `push.sh` → `node drop-old-pins` → `manifest sign` + `publish` |
| Push wake-ups | `deploy/push-key.sh fi-1 ~/fcm.json` → `otter-admin node set-push --label fi-1` → `manifest sign` + `manifest publish` |
| Daily DB backups | on the server: `/usr/local/lib/otter/backup.sh --install` |
| Uninstall | on the server: `/usr/local/lib/otter/uninstall.sh [--purge]` |

## News (Otter news, D64–D69)

Members see news as messages from «Выдра» in the chat «Новости Выдры». They are signed by the **news key**, which
lives in the desktop keyring (GNOME Secret Service, service `ottermsg-news`); nodes and phones accept only keys
listed in the current manifest.

One-time setup (desktop session unlocked):

```bash
otter-admin news init           # creates the key in the keyring, adds it to ~/.otter-admin/news_keys.json
otter-admin manifest sign       # asks for the admin passphrase; the manifest now lists the news key
otter-admin manifest publish
otter-admin news show           # listed keys; "(this keyring)" marks the one held here
```

Releasing an app version (APK signed with the release keystore, not the debug key):

```bash
deploy/release-apk.sh 0.6.0 path/to/app-release.apk [--no-news]
```

It refuses a debug-signed APK or a versionName ≠ VERSION, copies the APK to every node (`otter-node apk import`,
newest 2 kept), then — from a terminal, unless `--no-news` — opens the news dialog with an «Обновить» button for
this APK. `upgrade-all.sh VERSION` opens the same dialog (without the button) after a successful run.

The dialog (`deploy/news-dialog.sh VERSION [--apk FILE --version-code N]`) reads the draft `dist/news/VERSION.md`
(sections `## ru` and `## en`; `dist/` is gitignored), shows each language and asks
«[о]тправить / [и]зменить / [п]ропустить» (`o`/`e`/`s` work too; edit opens `$EDITOR`, default `nano`, and the edit
is saved back to the draft), then «Отправить? [y/N]». Nothing is sent unless you answer `y`.

By hand: `otter-admin announce --ru ru.txt --en en.txt [--apk F --version-name V --version-code N] [--via LABEL]`
publishes to every node directly (succeeds if at least one took it; the nodes replicate it to the rest).
`announce --list` shows what was sent (date, id, text, `[APK v]`, `[deleted]`); `announce --delete ID` (a prefix of
the id from `--list`) removes one from every phone.

Lost or leaked news key: `otter-admin news revoke --pub HEX` (from `news show`), then `manifest sign` +
`manifest publish`; nodes and phones drop everything it signed. Then `news init` creates a new key.

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
deploy/test/scripts_test.sh     # offline: hosts, add-node, status, upgrade-all, release-apk, news dialog (stubbed ssh)
deploy/test/e2e.sh [--keep]     # disposable Debian 12 VM (QEMU/KVM): install, upgrade, rollback, backup, uninstall
deploy/test/e2e-mesh.sh [--keep] # two VMs: add-node, replication, status, upgrade-all (needs internet in the VMs)
make deploy-test                # all four: scripts, bundle, e2e, e2e-mesh
```
