#!/usr/bin/env bash
# Builds dist/bundle-<label>.tar.gz for one node. Usage: make-bundle.sh <label> [version]
source "$(dirname "$0")/lib.sh"
label=${1:?usage: make-bundle.sh <label> [version]}
version=${2:-}
if [[ -z "$version" ]]; then
  version=$( (ls "$ROOT"/dist/otter-node_*_linux_amd64 2>/dev/null || true) | sed -E 's/.*otter-node_(.*)_linux_amd64/\1/' | sort -V | tail -n1)
fi
[[ -n "$version" ]] || die "no release in dist/ (make release VERSION=x.y.z)"
for arch in amd64 arm64; do [[ -f "$ROOT/dist/otter-node_${version}_linux_$arch" ]] || die "missing dist/otter-node_${version}_linux_$arch"; done
node_env "$label"
[[ "$OTTER_KIND" == wss ]] || die "node $label has a plain endpoint (development only); bundles need TLS"
if version_ge "$version" 0.8.0 && ! [[ "${OTTER_IP:-}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  die "node $label has no IPv4 address recorded (TURN relay_ip): otter-admin node set-ip --label $label --ip IP"
fi
[[ -f "$ADMIN_DIR/manifest.bin" ]] || die "no signed manifest: run 'otter-admin manifest sign'"
# the pin is unique per node, so this also checks that the manifest lists the node
manifest=$(admin manifest show) || die "manifest.bin does not verify"
grep -qF "\"$OTTER_PIN\"" <<< "$manifest" || die "the signed manifest does not list node $label with pin $OTTER_PIN: run 'otter-admin manifest sign'"

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
b="$work/bundle-$label"
mkdir -p "$b/site" "$b/invites"
say "bundle $label, otter-node $version"
cp "$ROOT/dist/otter-node_${version}_linux_amd64" "$b/otter-node-amd64"
cp "$ROOT/dist/otter-node_${version}_linux_arm64" "$b/otter-node-arm64"
cp "$OTTER_NODE_DIR/node.key" "$b/node.key"
cp "$OTTER_TLS_CERT" "$b/tls.crt"
cp "$OTTER_TLS_KEY" "$b/tls.key"
cp "$ADMIN_DIR/manifest.bin" "$b/manifest.bin"
export OTTER_LABEL OTTER_NETWORK_PUB OTTER_PORT OTTER_PATH
envsubst '${OTTER_LABEL} ${OTTER_NETWORK_PUB} ${OTTER_PORT} ${OTTER_PATH}' < "$ROOT/deploy/templates/node.toml" > "$b/node.toml"
# [turn] only for 0.8.0+: older binaries refuse unknown config keys
if version_ge "$version" 0.8.0; then
  export OTTER_IP
  envsubst '${OTTER_IP}' < "$ROOT/deploy/templates/node.toml.turn" >> "$b/node.toml"
  say "TURN relay for calls on (relay_ip $OTTER_IP)"
fi
cp "$ROOT"/deploy/templates/otter-node.service "$ROOT"/deploy/templates/otter-backup.service "$ROOT"/deploy/templates/otter-backup.timer "$b/"
cp -r "$ROOT/deploy/templates/site/." "$b/site/"
cp "$ROOT"/deploy/bundle/*.sh "$b/"
chmod 0755 "$b"/*.sh "$b"/otter-node-*
host=$OTTER_HOST; if [[ "$host" == *:* ]]; then host="[$host]"; fi
cat > "$b/probe.env" <<ENV
OTTER_PROBE_URL=wss://$host:$OTTER_PORT$OTTER_PATH
OTTER_PROBE_PIN=$OTTER_PIN
OTTER_NODE_ID=$OTTER_NODE_ID
OTTER_PORT=$OTTER_PORT
ENV
: > "$ROOT/dist/bundle-$label.invites"
shopt -s nullglob
for f in "$ADMIN_DIR"/invites/*.bin; do
  cp "$f" "$b/invites/"; echo "$f" >> "$ROOT/dist/bundle-$label.invites"; say "including bootstrap invite $(basename "$f")"
done
(cd "$b" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
umask 077
tar -C "$work" -czf "$ROOT/dist/bundle-$label.tar.gz" "bundle-$label"
chmod 0600 "$ROOT/dist/bundle-$label.tar.gz"
say "wrote dist/bundle-$label.tar.gz (contains private keys; push.sh deletes it after a successful install)"
