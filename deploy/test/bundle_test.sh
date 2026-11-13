#!/usr/bin/env bash
# Offline bundle test: builds a bundle from a throwaway admin dir and checks its contents and config.
set -euo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
fail() { echo "bundle test: FAIL: $*" >&2; exit 1; }
export OTTER_ADMIN_DIR="$work/admin" OTTER_ADMIN_PASSPHRASE=bundle-test-passphrase
make -s build
make -s release VERSION=0.0.0-bundletest >/dev/null
bin/otter-admin --dir "$OTTER_ADMIN_DIR" network init >/dev/null
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node add --label t1 --wss-host chat.example.org --ip 203.0.113.10 >/dev/null
# a bundle before the manifest lists the node is refused
if deploy/make-bundle.sh t1 0.0.0-bundletest >/dev/null 2>&1; then fail "bundle built without a signed manifest"; fi
bin/otter-admin --dir "$OTTER_ADMIN_DIR" manifest sign >/dev/null
bin/otter-admin --dir "$OTTER_ADMIN_DIR" invite bootstrap >/dev/null
deploy/make-bundle.sh t1 0.0.0-bundletest
[[ "$(stat -c %a dist/bundle-t1.tar.gz)" == 600 ]] || fail "bundle mode"
[[ "$(wc -l < dist/bundle-t1.invites)" == 1 ]] || fail "invites list"
tar -C "$work" -xzf dist/bundle-t1.tar.gz
b="$work/bundle-t1"
(cd "$b" && sha256sum --quiet -c SHA256SUMS)
for f in otter-node-amd64 otter-node-arm64 node.key tls.crt tls.key manifest.bin node.toml probe.env otter-node.service \
         otter-backup.service otter-backup.timer site/index.html install.sh uninstall.sh backup.sh health.sh; do
  [[ -e "$b/$f" ]] || fail "missing $f"
done
ls "$b"/invites/*.bin >/dev/null || fail "no invite"
grep -q '^ExecStart=/usr/local/bin/otter-node run --config /etc/otter/node.toml$' "$b/otter-node.service" || fail "unit"
if grep -qi otter "$b/site/index.html"; then fail "decoy page names the product"; fi
grep -q '^OTTER_PROBE_URL=wss://chat.example.org:27443/' "$b/probe.env" || fail "probe.env"
[[ "$("$b/otter-node-amd64" version)" == 0.0.0-bundletest ]] || fail "binary version"
sed -e "s#/etc/otter#$b#g" -e "s#/var/lib/otter#$work/data#g" "$b/node.toml" > "$work/node.toml"
"$b/otter-node-amd64" check --config "$work/node.toml"
if grep -q '^\[turn\]' "$b/node.toml"; then fail "pre-0.8.0 bundle has [turn]"; fi
# 0.8.0+ bundles carry [turn] with the node's IP; with a secret from `turn keygen` the config passes the check
for a in amd64 arm64; do cp "dist/otter-node_0.0.0-bundletest_linux_$a" "dist/otter-node_0.8.0-bundletest_linux_$a"; done
deploy/make-bundle.sh t1 0.8.0-bundletest >/dev/null
rm -f dist/otter-node_0.8.0-bundletest_*
tar -xzOf dist/bundle-t1.tar.gz bundle-t1/node.toml > "$work/node8.src.toml"
grep -q '^relay_ip = "203.0.113.10"$' "$work/node8.src.toml" || fail "0.8.0 bundle relay_ip: $(cat "$work/node8.src.toml")"
sed -e "s#/etc/otter#$b#g" -e "s#/var/lib/otter#$work/data#g" -e "/^\[turn\]/a secret_file = \"$work/turn.secret\"" \
  "$work/node8.src.toml" > "$work/node8.toml"
if "$b/otter-node-amd64" check --config "$work/node8.toml" >/dev/null 2>&1; then fail "check passed without the TURN secret"; fi
"$b/otter-node-amd64" turn keygen --config "$work/node8.toml" >/dev/null
[[ "$(stat -c %a "$work/turn.secret")" == 640 ]] || fail "turn secret mode"
"$b/otter-node-amd64" check --config "$work/node8.toml" | grep -q '^ok turn secret' || fail "turn check line"
rm -f dist/bundle-t1.tar.gz dist/bundle-t1.invites
# a rotated (staged) certificate is bundled once the manifest is re-signed
bin/otter-admin --dir "$OTTER_ADMIN_DIR" node rotate-tls --label t1 >/dev/null
if deploy/make-bundle.sh t1 0.0.0-bundletest >/dev/null 2>&1; then fail "staged pin not in the manifest yet, bundle must be refused"; fi
bin/otter-admin --dir "$OTTER_ADMIN_DIR" manifest sign >/dev/null
deploy/make-bundle.sh t1 0.0.0-bundletest >/dev/null
rm -rf "$b" && tar -C "$work" -xzf dist/bundle-t1.tar.gz
cmp -s "$b/tls.crt" "$OTTER_ADMIN_DIR/nodes/t1/tls.new.crt" || fail "staged certificate not bundled"
rm -f dist/bundle-t1.tar.gz dist/bundle-t1.invites dist/*0.0.0-bundletest*
(cd dist && if ls otter-*_* >/dev/null 2>&1; then sha256sum otter-*_* > SHA256SUMS; else rm -f SHA256SUMS; fi)
echo "bundle test: ok"
