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

Options: `--ip` (repeat for IPv6), `--domain`, `--wss-port P`, `--ssh-port N`, `--version V` (bundle that release),
`--dial-out-only` / `--no-dial-out-only` (see REALITY below; without either it asks on a terminal, default No, and
says No when run without one).
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
| Upgrade (auto rollback) | `deploy/upgrade.sh root@203.0.113.10 dist/otter-node_1.2.1_linux_amd64` (exit 0 ok, 2 rolled back, 3 manual; a rollback also restores `node.toml` from `node.toml.prev`) |
| All nodes at a glance | `deploy/status.sh` (target, version, hello, service, DB counts, disk, push, then the last 5 connectivity log lines per node; exit 1 on any problem) |
| REALITY on a node | `deploy/reality-setup.sh fi-1 --dest dl.google.com [--port 443] [--force]` → `manifest sign` + `manifest publish` (below) |
| Upgrade every node | `deploy/upgrade-all.sh 1.2.1 [--only fi-1] [--no-news]` (builds the release if missing, skips nodes already on it, stops at the first rollback; exit 0 / 2 rolled back / 3 manual; then offers the news dialog) |
| SSH target of a node | `deploy/hosts.sh set fi-1 root@203.0.113.10 [port]` / `get` / `list` / `rm` |
| New IP | `otter-admin node set-ip --label fi-1 --ip 198.51.100.7` → DNS → `push.sh` |
| Rotate TLS | `node rotate-tls` → `manifest sign` + `manifest publish` → apps update → `push.sh` → `node drop-old-pins` → `manifest sign` + `publish` |
| Push wake-ups | `deploy/push-key.sh fi-1 ~/fcm.json` → `otter-admin node set-push --label fi-1` → `manifest sign` + `manifest publish` |
| Daily DB backups | on the server: `/usr/local/lib/otter/backup.sh --install` |
| Uninstall | on the server: `/usr/local/lib/otter/uninstall.sh [--purge]` |

## REALITY and dial-out-only nodes (M7, D70–D74)

**When.** A node inside a censored network (Russia) cannot be dialed from abroad and its outgoing WSS gets
throttled. Mark it **dial-out-only** (it dials the other nodes, nobody dials it) and give the foreign nodes it talks
to a **VLESS+REALITY** listener on :443 (D72). To a censor's probe that port looks like the camouflage site; only
peers holding the node's public key get through. Phones still use WSS (D75).

**Dial-out-only.** `add-node.sh` asks «Is LABEL inside a censored network?» for a new node (or pass
`--dial-out-only` / `--no-dial-out-only`). For an existing node: `otter-admin node set-dial-out-only --label L
[--off]` → `manifest sign` + `manifest publish`. A re-run of `add-node.sh` never changes the flag.

**Camouflage site.** Pick a big foreign TLS 1.3 + HTTP/2 site that is not blocked and test it **from the node**
(that is where REALITY forwards probes):

```bash
ssh root@fi-1 /usr/local/bin/otter-node reality-check dl.google.com www.apple.com www.microsoft.com
```

The check includes a REALITY handshake through the site on loopback: sites whose handshake records are over 8 KB
(www.microsoft.com, with its long certificate chain, on 2026-11-13) pass plain TLS but REALITY cannot mirror them.

**Setup** (node on 0.7.0+; `deploy/upgrade-all.sh` first):

```bash
deploy/reality-setup.sh fi-1 --dest dl.google.com         # --port 443 by default; --force replaces an existing [reality]
otter-admin manifest sign && otter-admin manifest publish  # your terminal (asks for the admin passphrase)
```

It runs `reality-check` on the node, writes `[reality]` into `node.toml.new`, generates the private key on the node
(`/etc/otter/reality.key`, never leaves it), validates with `otter-node check`, adds a systemd drop-in with
`CAP_NET_BIND_SERVICE` (new installs have it in the unit), opens the port in an active ufw, swaps the config,
restarts and waits for the health check and the `"reality on"` log line. On any failure the previous `node.toml` is
back in place (`node.toml.pre-reality` keeps the pre-REALITY copy). Then it adds the endpoint (the node's first
recorded IP, see `otter-admin node set-ip`) with `otter-admin node add-reality`. Allow the port in the provider's
cloud firewall too. Note: `push.sh`/`add-node.sh` re-installs write a fresh `node.toml` without `[reality]`; run
`reality-setup.sh LABEL --dest … --force` again afterwards (the key file is kept, so the manifest stays valid).

**Connectivity log.** Every node keeps the last 200 merged lines of peer connection outcomes (D74):

```bash
ssh root@fi-1 'runuser -u otter -- /usr/local/bin/otter-node netlog --config /etc/otter/node.toml [--limit 50] [--json]'
# 2026-11-20 10:02–14:55  ru-1  reality  in  ok  ×143
```

`deploy/status.sh` prints the last 5 lines of each node. `fail` lines carry a failure class (`timeout`, `reset`,
`reset_after_kb` = throttling, `tls`, …); an endpoint throttled 3× within 24 h is tried last for a day (D73).

**Rollback.** `upgrade.sh` keeps `node.toml.prev` and restores it with the old binary. Before downgrading a node
below 0.7.0 by hand, remove its `[reality]` section (older binaries refuse unknown config keys); the REALITY
endpoint left in the manifest then only costs peers one failed dial before WSS. The drop-in
`/etc/systemd/system/otter-node.service.d/reality.conf` may stay.

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
deploy/test/scripts_test.sh     # offline: hosts, add-node, status, upgrade-all, release-apk, news dialog, reality-setup (stubbed ssh)
deploy/test/e2e.sh [--keep]     # disposable Debian 12 VM (QEMU/KVM): install, upgrade, rollback, backup, uninstall
deploy/test/e2e-mesh.sh [--keep] # two VMs: add-node, replication, status, upgrade-all (needs internet in the VMs)
make deploy-test                # all four: scripts, bundle, e2e, e2e-mesh
```
