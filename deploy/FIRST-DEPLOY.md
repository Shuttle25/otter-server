# First real deployment — runbook

One VPS, a **new** family network, your own domain. Everything runs from this PC (the "admin machine") in
`otter-server/`; the server only receives a bundle over SSH. Background and reasons: `docs/11-deployment.md`.

Replace the placeholders everywhere:

| Placeholder | Example | Meaning |
|-------------|---------|---------|
| `LABEL` | `fi-1` | short node name: lowercase letters, digits, `-` |
| `DOMAIN` | `chat.example.org` | hostname the apps connect to (your domain) |
| `IP` | `203.0.113.10` | the server's public IPv4 (add `--ip <IPv6>` too if it has one) |
| `VERSION` | `0.1.0` | release version you choose |

## What gets installed on the server

`install.sh` (inside the bundle, run as root) does only this:

| What | Where |
|------|-------|
| system user `otter` (no shell, no login) | — |
| node binary | `/usr/local/bin/otter-node` (previous one kept as `otter-node.prev` on upgrades) |
| config, node key, TLS key + certificate, signed manifest, health-check settings | `/etc/otter/` (root:otter, 0640) |
| database + decoy web page | `/var/lib/otter/` (otter, 0700) |
| backups (when you enable them) | `/var/backups/otter/` |
| helper scripts `install.sh uninstall.sh backup.sh health.sh` | `/usr/local/lib/otter/` |
| systemd units `otter-node.service`, `otter-backup.service`, `otter-backup.timer` | `/etc/systemd/system/` |
| `systemd-timesyncd` (only if no chrony/timesyncd is running) | apt package |
| ufw rules for SSH and port 27443 (only if ufw is already active; otherwise it just warns) | — |

Nothing else: no Docker, no web server, no database server. The node listens on **TCP 27443** only (WSS with a
self-signed certificate whose key is pinned in the apps; `https://DOMAIN:27443/` shows a neutral "Under maintenance"
page). The network admin key never leaves this PC. `uninstall.sh` removes everything (`--purge` also deletes data).

## 0. Server prerequisites

- Debian 12/13 or Ubuntu 22.04/24.04, amd64 or arm64, ≥ 1 GB RAM.
- Root SSH login with a key from this PC works: `ssh root@IP true`.
  Non-standard port or key file: `export OTTER_SSH_PORT=2222 OTTER_SSH_OPTS="-i ~/.ssh/otter"` before the scripts.
- Provider/cloud firewall: allow inbound **TCP 22** (or your SSH port) and **TCP 27443**; nothing else is needed.
- Recommended: `apt install unattended-upgrades`, `PermitRootLogin prohibit-password` in sshd.

## 1. Build (this PC)

```bash
cd otter-server
make check                          # tests must pass
make build                          # bin/otter-admin, bin/otter-node (used by the scripts)
make release VERSION=VERSION        # dist/otter-node_VERSION_linux_{amd64,arm64} + SHA256SUMS
```

## 2. Create the network (this PC, once)

```bash
bin/otter-admin network init        # asks for a passphrase (≥ 12 characters)
```

Back up `~/.otter-admin/` (network key, node keys, TLS keys) and the passphrase now — USB stick / password manager.
Without them you can't sign manifests, rebuild bundles or add nodes.

## 3. Register the node and DNS

```bash
bin/otter-admin node add --label LABEL --wss-host DOMAIN --ip IP
bin/otter-admin manifest sign
bin/otter-admin dns records         # prints the A (and AAAA) record(s) to create
```

Create the printed record(s) at your DNS provider (TTL 300), then wait until this says `ok`:

```bash
bin/otter-admin dns check --label LABEL
```

## 4. Bootstrap invite (first member)

```bash
bin/otter-admin invite bootstrap    # prints an otter://join/… link and a QR code; valid 7 days (--ttl 168h)
```

Keep the link/QR: it is for the **first** phone. The invite record goes into the bundle automatically.

## 5. Install

```bash
deploy/push.sh LABEL root@IP
```

It builds `dist/bundle-LABEL.tar.gz` (contains private keys, mode 0600), uploads it, runs `install.sh`, removes the
remote copy, runs the health checks and prints a table — every row must be `PASS`, ending with
`all checks passed for LABEL`. Then it deletes the local bundle.

Manual alternative (same result): `deploy/make-bundle.sh LABEL`, copy `dist/bundle-LABEL.tar.gz` to the server, and
there `tar xzf bundle-LABEL.tar.gz && ./bundle-LABEL/install.sh`; afterwards `deploy/check.sh LABEL root@IP` here.

Register the server for the day-2 scripts: `deploy/hosts.sh set LABEL root@IP` (add the port as a third argument
if SSH is not on 22). An already deployed node is registered the same way, e.g. `deploy/hosts.sh set eeee root@eeee`.

Single node? Enable daily DB backups (7 kept): `ssh root@IP /usr/local/lib/otter/backup.sh --install`.

## 6. Phones

The phones are joined to the dev network; an app holds one account, so joining the new network means starting
fresh (the dev-network chats are lost on that phone).

1. Install the latest app build (M1.5 debug APK, or staging/release) and clear its data
   (Settings → Apps → Otter → Storage → Clear data), or uninstall and reinstall.
2. Phone 1: "Join with an invite" → scan the bootstrap QR / paste the link → name, username, recovery phrase.
3. Phone 1: Settings → "Пригласить в семью" → phone 2 scans that QR.
4. Write in both directions; rename on one phone (Settings → profile → Имя) and check the other.

## Second node

A network with a single node has no failover, so add a second one soon:

```bash
deploy/add-node.sh LABEL2 root@IP2 --ip IP2 [--domain DOMAIN2]
```

It registers, signs, installs and publishes the manifest to the first node (no restart). Phones learn the new node
on their next connection. If it stops, fix the cause and re-run the same command.

## Push notifications (optional)

Without push, phones check for messages every 15 minutes («Экономия батареи»). With a Firebase service-account key
on at least one node, a message wakes a sleeping phone within seconds. Creating the Firebase project and downloading
the key (`fcm.json`) is described in `otter-android/README.md` ("Push / Firebase"). The key never goes into git,
bundles or the admin dir. The node must already run a release with M5 (`deploy/upgrade-all.sh`): an older
`otter-node` rejects the `[push]` section that `push-key.sh` adds.

```bash
deploy/push-key.sh LABEL ~/fcm.json           # installs /etc/otter/fcm.json (0640 root:otter), restarts, expects "push on"
bin/otter-admin node set-push --label LABEL   # marks the node push_capable in the manifest
bin/otter-admin manifest sign && bin/otter-admin manifest publish
deploy/status.sh                              # PUSH column: on
```

To turn it off again: `bin/otter-admin node set-push --label LABEL --off`, sign and publish, then remove
`/etc/otter/fcm.json` on the server and restart `otter-node`.

## 7. Upgrade and rollback test

```bash
deploy/upgrade-all.sh <next, e.g. 0.1.1>      # builds the release, upgrades every registered node
# expected: summary row "LABEL  upgraded <old> → <next>", exit 0

printf '#!/bin/sh\nexit 1\n' > /tmp/broken-otter-node
deploy/upgrade.sh root@IP /tmp/broken-otter-node; echo "exit $?"
# expected: "rolled back", exit 2; the node still reports <next>; chats keep working
deploy/check.sh LABEL root@IP
```

## 8. Report back

Fill rows 15–18 of `otter-android/docs/m1.5-manual-test.md` (or just tell me what each step printed), and note any
place where this runbook or `docs/11-deployment.md` didn't match reality.

## Useful later

| Task | Command |
|------|---------|
| Logs | `ssh root@IP journalctl -u otter-node -f` |
| All nodes at a glance | `deploy/status.sh` |
| Push wake-ups | `deploy/push-key.sh LABEL ~/fcm.json` → `bin/otter-admin node set-push --label LABEL` → `manifest sign` + `manifest publish` |
| Health | `deploy/check.sh LABEL root@IP` |
| Server IP changed | `bin/otter-admin node set-ip --label LABEL --ip NEW` → update DNS → `deploy/push.sh LABEL root@NEW` (pin unchanged) |
| Remove the node | `ssh root@IP /usr/local/lib/otter/uninstall.sh --purge` |
