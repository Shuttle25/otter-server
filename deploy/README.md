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
| Upgrade (auto rollback) | `deploy/upgrade.sh root@203.0.113.10 dist/otter-node_1.2.1_linux_amd64` (exit 0 ok, 2 rolled back, 3 manual; a rollback also restores `node.toml` from `node.toml.prev`; the DB copy is 0600, the newest 3 `pre-upgrade-*.db` are kept, and the copy, pruning and restore run as `otter`, D82/D84) |
| All nodes at a glance | `deploy/status.sh` (target, version, hello, service, DB counts (+ `turn_allocs=`), disk, push, TURN, then the last 5 connectivity log lines per node; exit 1 on any problem) |
| TURN relay (calls) on a node | `deploy/turn-setup.sh fi-1 [--if-missing] [--force]` (0.8.0+; `upgrade-all.sh` runs it; below) |
| REALITY on a node | `deploy/reality-setup.sh fi-1 --dest dl.google.com [--port 443] [--force]` → `manifest sign` + `manifest publish` (below) |
| Upgrade every node | `deploy/upgrade-all.sh 1.2.1 [--only fi-1] [--no-news] [--no-turn]` (builds the release if missing, skips nodes already on it, stops at the first rollback; exit 0 / 2 rolled back / 3 manual; 0.8.0+: TURN on each node unless `--no-turn`; then offers the news dialog) |
| SSH target of a node | `deploy/hosts.sh set fi-1 root@203.0.113.10 [port]` / `get` / `list` / `rm` |
| New IP | `otter-admin node set-ip --label fi-1 --ip 198.51.100.7` → DNS → `push.sh` |
| Rotate TLS | `node rotate-tls` → `manifest sign` + `manifest publish` → apps update → `push.sh` → `node drop-old-pins` → `manifest sign` + `publish` |
| Push wake-ups | `deploy/push-key.sh fi-1 ~/fcm.json` → `otter-admin node set-push --label fi-1` → `manifest sign` + `manifest publish` |
| Daily DB backups | on the server: `/usr/local/lib/otter/backup.sh --install` (7 copies, 0600 in the 0700 `/var/backups/otter`) |
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

## CDN-fronted endpoint (Cloudflare, D130–D131)

**When.** A censor freezes every connection to a foreign node's address after a few KB (seen from ru-1 to eeee,
2026-11-15: WSS and REALITY on that address both froze, while a CDN passed bulk data). From 0.9.1 nodes ping peer
sessions every 25 s and end a session after 60 s without a pong; such a frozen outbound session counts as
`reset_after_kb` and a handshake failing after a good dial marks the endpoint failed (D130), so the dialer moves on to
the next endpoint. Give the frozen node an extra, unpinned WSS endpoint behind a CDN (D131): priority 10, so nodes and
phones use it only after the direct endpoints fail. `Endpoints[0]` stays the node's own pinned endpoint.

First effect, before any CDN (on the node that cannot get through, e.g. ru-1):

```bash
ssh root@ru-1 'runuser -u otter -- /usr/local/bin/otter-node netlog --config /etc/otter/node.toml --limit 15'
# eeee  ping  out  fail timeout
# wss:<eeee-ip>:27443  out  fail reset_after_kb (frozen: …)
```

**1. CDN dashboard** (a domain already in the CDN account; not the name phones use for the node, so it can be dropped
without touching anything else). `<cdn-host>` is that name; it never goes into a repo.

1. DNS → Add record: type `A`, name = the `<cdn-host>` label, IPv4 `<eeee-ip>`, **Proxy status: Proxied** (orange).
2. Rules → Origin Rules → Create: "Hostname equals `<cdn-host>`" → Destination port: **rewrite to 27443** (the node's
   WSS port).
3. Rules → Configuration Rules → Create: "Hostname equals `<cdn-host>`" → SSL: **Full** (not "Full (strict)": the
   node's certificate is self-signed and pinned). Leave the zone's default SSL mode as it is.
4. Network → WebSockets: **On** (default).
5. Do **not** enable caching rules, "Always use HTTPS" redirects to other ports, Rocket Loader or Bot Fight Mode for
   this name; they can break the WebSocket upgrade.

**2. Test the CDN path** (from the laptop, then from the node that cannot get through):

```bash
curl -s -o /dev/null --max-time 10 -w 'site: %{http_code}\n' https://<cdn-host>/
curl -s -o /dev/null --max-time 5 --http1.1 -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H "Sec-WebSocket-Key: $(head -c 16 /dev/urandom | base64)" \
  -w 'peer: %{http_code}\n' https://<cdn-host>/<secret-path>/peer
```

`<secret-path>` is the part after the port in the node's `otter-admin node list` WSS line (without the leading `/`).
Expected: `site: 200` (the camouflage site through the CDN), `peer: 101`. `site: 52x` = origin rule or SSL mode
wrong; `peer: 400/426` = WebSockets off or the path wrong.

**3. Add the endpoint and publish** (laptop, admin binary 0.9.1+; `manifest sign` asks for the passphrase):

```bash
otter-admin node add-wss --label eeee --host <cdn-host> --port 443 --cdn --priority 10
otter-admin node list                     # a second eeee WSS line with cdn=true pin=-
otter-admin manifest sign
otter-admin manifest publish --via eeee --via ru-1
```

Expected: `node eeee: WSS <cdn-host>:443 cdn=true priority=10 pins=0`; publish prints `ok` (or `already current`)
per node. If publishing via ru-1 times out, eeee's copy still reaches ru-1 over the next short session.

**4. Confirm** (on ru-1, after ~15 min):

```bash
ssh root@ru-1 'runuser -u otter -- /usr/local/bin/otter-node netlog --config /etc/otter/node.toml --limit 10'
ssh root@ru-1 'journalctl -u otter-node --since "-30min" -o cat | grep -E "peer session (up|down)" | tail -5'
```

Expected: newest netlog lines `wss:<cdn-host>:443 out ok`; one `peer session up` and no `down` after it. Then send a
photo from a phone on ru-1 to a phone on eeee.

**Rollback** (only if the CDN path misbehaves):

```bash
otter-admin node remove-endpoint --label eeee --host <cdn-host> --port 443
otter-admin manifest sign && otter-admin manifest publish --via eeee --via ru-1
```

then delete the DNS record and both rules in the CDN dashboard. `remove-endpoint` refuses the node's own endpoint
(`Endpoints[0]`).

## Calls (TURN, M8, D77)

Every 0.8.0+ node embeds a TURN relay for 1:1 audio calls. Phones get short-lived credentials from their node
(`turn.credentials`); the relay only forwards encrypted media. It listens on **UDP 3478, TCP 3478, TLS 5349** (TLS
uses the node's [wss] certificate) and relays on **UDP 49160–49200**. Config in `node.toml`:

```toml
[turn]
enabled = true
relay_ip = "203.0.113.10"   # the node's public IPv4 (first IP from otter-admin node set-ip)
```

The per-node secret `/etc/otter/turn.secret` (32 random bytes, `root:otter 0640`) is created on the node by
`otter-node turn keygen` and never leaves it: not in bundles, not in `~/.otter-admin`, never printed.
`otter-node check` reports `ok turn secret … relay IP:49160-49200`; `deploy/status.sh` shows `TURN on/off` (`-` =
no `[turn]`, e.g. before 0.8.0) and `turn_allocs=` / `turn_relayed_bytes=` in STATS.

**New nodes.** `make-bundle.sh` adds `[turn]` (template `templates/node.toml.turn`, `relay_ip` = the node's
recorded IPv4) only to bundles of 0.8.0 or newer; `install.sh` creates the secret if missing. `push.sh` asks on
your terminal whether to allow the TURN ports in an **active ufw** on the node (default No; without a terminal it
is No and `install.sh` prints the `ufw allow` commands instead).

**Existing nodes** get it after their binary is 0.8.0 (older binaries refuse unknown keys):

```bash
deploy/upgrade-all.sh 0.8.0                # upgrades, then runs turn-setup.sh LABEL --if-missing per node
deploy/turn-setup.sh fi-1                  # by hand / retry; --force rewrites an existing [turn] (secret kept)
```

`turn-setup.sh` refuses nodes below 0.8.0, writes `[turn]` into `node.toml.new`, creates the secret if missing,
validates with `otter-node check`, keeps `node.toml.pre-turn`, swaps, restarts and waits for the health check and
the `"turn on"` log line. On any failure the previous `node.toml` is back in place. If ufw is active it asks (on a
terminal, default No) before `ufw allow 3478/udp 3478/tcp 5349/tcp 49160:49200/udp`, run only after TURN is up;
otherwise it prints those commands. A TURN failure in `upgrade-all.sh` does not stop the rollout: the summary says
`TURN NOT ENABLED`; retry with `turn-setup.sh LABEL`.

**Cloud firewall.** If the provider has one (Hetzner, …), open UDP 3478, TCP 3478, TCP 5349 and UDP 49160–49200 to
the node there yourself; the scripts only remind you.

**Rollback.** `upgrade.sh` restores `node.toml.prev` with the old binary, so a failed 0.8.0 upgrade never leaves
`[turn]` behind. 0.7.0 binaries refuse `[turn]`: before a manual downgrade below 0.8.0, remove the `[turn]` section
(or restore `node.toml.pre-turn`). `/etc/otter/turn.secret` may stay. Re-installs (`push.sh`) rewrite `node.toml`
from the template, which for 0.8.0+ bundles includes `[turn]` again (the secret is kept).

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

It refuses a debug-signed APK or a versionName ≠ VERSION, and refuses to release while any node runs otter-node
older than 0.8.3. It streams the APK over ssh into a root-only temp directory, checks its SHA-256 and imports it as
`otter` (nodes must run 0.8.3+; `runuser -u otter -- otter-node apk import … - < APK`, newest 2 kept; `apk import`
refuses to run as root, D82), then — from a terminal, unless `--no-news` — opens the news dialog with an «Обновить» button for
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
deploy/test/scripts_test.sh     # offline: hosts, add-node, status, upgrade-all, release-apk, news dialog, reality-setup, turn-setup (stubbed ssh)
deploy/test/e2e.sh [--keep]     # disposable Debian 12 VM (QEMU/KVM): install, upgrade, rollback, backup, uninstall
deploy/test/e2e-mesh.sh [--keep] # two VMs: add-node, replication, status, upgrade-all (needs internet in the VMs)
make deploy-test                # all four: scripts, bundle, e2e, e2e-mesh
```
