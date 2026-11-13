#!/usr/bin/env bash
# Installs a node from its bundle. Usage: push.sh <label> <root@host>
source "$(dirname "$0")/lib.sh"
label=${1:?usage: push.sh <label> <root@host>}; target=${2:?usage: push.sh <label> <root@host>}
bundle="$ROOT/dist/bundle-$label.tar.gz"
[[ -f "$bundle" ]] || "$ROOT/deploy/make-bundle.sh" "$label"
# TURN ports (M8) change the node's firewall: asked here, on the admin's terminal (default No); install.sh only
# prints the ufw commands otherwise
turn_ufw=0
if [[ -t 0 ]] && grep -q '^\[turn\]' <<< "$(tar -xzOf "$bundle" "bundle-$label/node.toml")"; then
  read -r -p "If ufw is active on $label, allow the TURN ports for calls ($TURN_PORTS)? [y/N] " ans
  if [[ "$ans" =~ ^[yYдД] ]]; then turn_ufw=1; fi
fi
say "uploading bundle to $target"
rdir=$(remote "$target" mktemp -d /root/otter-bundle.XXXXXX)
upload "$target" "$bundle" "$rdir/"
say "running install.sh on $target"
if ! remote "$target" "cd '$rdir' && tar xzf bundle-$label.tar.gz && OTTER_TURN_UFW=$turn_ufw ./bundle-$label/install.sh; rc=\$?; rm -rf '$rdir'; exit \$rc"; then
  die "install failed on $target; the local bundle is kept in dist/"
fi
"$ROOT/deploy/check.sh" "$label" "$target"
if [[ -s "$ROOT/dist/bundle-$label.invites" ]]; then
  mkdir -p "$ADMIN_DIR/invites/delivered"
  while read -r f; do if [[ -f "$f" ]]; then mv "$f" "$ADMIN_DIR/invites/delivered/"; fi; done < "$ROOT/dist/bundle-$label.invites"
  say "bootstrap invite delivered; send its link to the first member"
fi
rm -f "$bundle" "$ROOT/dist/bundle-$label.invites"
say "done: $label on $target (local bundle deleted; make-bundle.sh can recreate it)"
