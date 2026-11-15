#!/usr/bin/env bash
# Copy a release-signed APK to every node, then offer the news dialog (D68, D69).
# Usage: release-apk.sh VERSION APK [--no-news]
source "$(dirname "$0")/lib.sh"
usage="usage: release-apk.sh VERSION APK [--no-news]"
version=${1:?$usage}; apk=${2:?$usage}; shift 2
news=1
while (( $# )); do case "$1" in --no-news) news=0; shift ;; *) die "$usage" ;; esac; done
[[ -f "$apk" ]] || die "no such file: $apk"
apk=$(realpath "$apk")
sdk=${ANDROID_HOME:-$(sed -n 's/^sdk.dir=//p' "$ROOT/../otter-android/local.properties" 2>/dev/null || true)}
bt=$(ls -d "$sdk"/build-tools/* 2>/dev/null | sort -V | tail -1 || true)
apksigner=$(command -v apksigner || echo "$bt/apksigner")
aapt2=$(command -v aapt2 || echo "$bt/aapt2")
[[ -x "$apksigner" && -x "$aapt2" ]] || die "apksigner/aapt2 not found (set ANDROID_HOME)"
certs=$("$apksigner" verify --print-certs "$apk") || die "APK signature does not verify"
if grep -q "CN=Android Debug" <<< "$certs"; then die "debug-signed APK: build the release with keystore.properties (D68)"; fi
badging=$("$aapt2" dump badging "$apk") || die "aapt2 cannot read $apk"
name=$(sed -n "s/.* versionName='\([^']*\)'.*/\1/p" <<< "$badging" | head -1)
code=$(sed -n "s/.* versionCode='\([0-9]*\)'.*/\1/p" <<< "$badging" | head -1)
[[ "$name" == "$version" ]] || die "APK versionName is '$name', expected $version"
[[ -n "$code" ]] || die "APK has no versionCode"
sha=$(sha256sum "$apk" | cut -d' ' -f1)
labels=$(node_labels)
for l in $labels; do host_lookup "$l" || die "node $l has no SSH target: deploy/hosts.sh set $l root@HOST"; done
# C3 (D82): nodes before 0.8.3 import APKs as root; refuse them before anything is sent
for l in $labels; do
  host_lookup "$l"
  export OTTER_SSH_PORT=$TARGET_PORT SSH_PORT=$TARGET_PORT
  v=$(remote "$TARGET" /usr/local/bin/otter-node version < /dev/null) || die "cannot reach $l"
  version_ge "$v" 0.8.3 || die "node $l runs otter-node $v: upgrade it to 0.8.3 or newer first (deploy/upgrade-all.sh)"
done
# The APK arrives on ssh stdin in a fresh root-only directory (mktemp -d: 0700, unpredictable name), is checked
# there, and reaches the importer, which runs as otter, only as an open file on its stdin. Root never opens a path
# the node user can write (C3, D82).
import_cmd='set -euo pipefail; d=$(mktemp -d /root/otter-apk.XXXXXX); trap '"'"'rm -rf "$d"'"'"' EXIT; cat > "$d/app.apk"; echo "$1  $d/app.apk" | sha256sum --quiet -c; runuser -u otter -- /usr/local/bin/otter-node apk import --config /etc/otter/node.toml - < "$d/app.apk"'
for l in $labels; do
  host_lookup "$l"
  export OTTER_SSH_PORT=$TARGET_PORT SSH_PORT=$TARGET_PORT
  say "copying APK $version ($code) to $l"
  remote "$TARGET" "bash -c $(printf '%q' "$import_cmd") import $sha" < "$apk" \
    || die "apk import on $l failed (run release-apk.sh again)"
done
say "APK $version ($code) is on every node (sha256 $sha)"
retry="deploy/news-dialog.sh $version --apk $apk --version-code $code"
if (( news )) && [[ -t 0 ]]; then
  "$ROOT/deploy/news-dialog.sh" "$version" --apk "$apk" --version-code "$code" || say "news not sent; retry: $retry"
else
  say "news: $retry"
fi
