#!/usr/bin/env bash
# Adds a node to the network and installs it; safe to re-run after a failure (docs/11 §11, §14).
# Usage: add-node.sh LABEL ROOT@HOST --ip IP [--ip IP]... [--domain NAME] [--wss-port PORT] [--ssh-port N] [--version V]
#        [--dial-out-only|--no-dial-out-only]   (asked on a terminal when neither is given; default No)
source "$(dirname "$0")/lib.sh"
usage="usage: add-node.sh LABEL ROOT@HOST --ip IP [--ip IP]... [--domain NAME] [--wss-port PORT] [--ssh-port N] [--version V] [--dial-out-only|--no-dial-out-only]"
label=${1:-}; target=${2:-}
[[ -n "$label" && -n "$target" && "$target" != --* ]] || die "$usage"
shift 2
ips=(); domain=""; wss_port=""; ssh_port=""; version=""; dial_out=""
while (( $# )); do
  case "$1" in
    --ip) ips+=("${2:?$usage}"); shift 2 ;;
    --domain) domain=${2:?$usage}; shift 2 ;;
    --wss-port) wss_port=${2:?$usage}; shift 2 ;;
    --ssh-port) ssh_port=${2:?$usage}; shift 2 ;;
    --version) version=${2:?$usage}; shift 2 ;;
    --dial-out-only) dial_out=1; shift ;;
    --no-dial-out-only) dial_out=0; shift ;;
    *) die "$usage" ;;
  esac
done
(( ${#ips[@]} )) || die "at least one --ip (the server's public address) is required; $usage"
if host_lookup "$label" && [[ "$TARGET" != "$target" ]]; then
  die "node $label is already registered to $TARGET (deploy/hosts.sh rm $label to change it)"
fi
trap 'rc=$?; if (( rc != 0 )); then echo "add-node stopped (exit $rc): fix the cause and re-run the same command; finished steps are skipped" >&2; fi' EXIT
existing=$(node_labels)
others=$(grep -vx "$label" <<< "$existing" || true)

if grep -qx "$label" <<< "$existing"; then
  say "node $label already exists: skipping node add (its addresses are not changed; use otter-admin node set-ip for that)"
else
  args=(--label "$label" --wss-host "${domain:-${ips[0]}}")
  for ip in "${ips[@]}"; do args+=(--ip "$ip"); done
  [[ -z "$wss_port" ]] || args+=(--wss-port "$wss_port")
  say "registering node $label"
  admin node add "${args[@]}"
  if [[ -z "$dial_out" ]]; then
    dial_out=0
    if [[ -t 0 ]]; then
      # dial_out_only only for a node that cannot accept inbound connections (e.g. behind NAT).
      # A node in Russia must NOT be dial-out-only: it is dialed from abroad (D132).
      read -r -p "Make $label dial-out-only? Only for a node that cannot accept inbound connections (e.g. behind NAT); it then dials the other nodes and is never dialed. Not for a node in Russia: it must be dialed from abroad (D132). [y/N] " ans
      [[ "$ans" =~ ^[yYдД] ]] && dial_out=1
    fi
  fi
  if (( dial_out )); then
    say "marking $label dial_out_only (D71)"
    admin node set-dial-out-only --label "$label"
  fi
fi
node_env "$label"
# the pin is unique per node, so a manifest containing it already lists the node (same test as make-bundle.sh)
if [[ -f "$ADMIN_DIR/manifest.bin" ]] && admin manifest show 2>/dev/null | grep -qF "\"$OTTER_PIN\""; then
  say "the signed manifest already lists $label"
else
  say "signing the manifest (asks for the admin passphrase)"
  admin manifest sign
fi
"$ROOT/deploy/hosts.sh" set "$label" "$target" ${ssh_port:+"$ssh_port"}

if [[ -n "$domain" ]]; then
  say "create these DNS records now (TTL 300):"
  admin dns records | grep -F "$domain" || true
  say "waiting for DNS (up to 30 min; Ctrl-C and re-run this command to resume)"
  for _ in $(seq 60); do
    if admin dns check --label "$label" >/dev/null 2>&1; then break; fi
    sleep 30
  done
  admin dns check --label "$label" || die "DNS for $domain is not correct yet"
fi

[[ -z "$version" ]] || "$ROOT/deploy/make-bundle.sh" "$label" "$version"
host_lookup "$label"
say "installing $label on $TARGET"
OTTER_SSH_PORT=$TARGET_PORT "$ROOT/deploy/push.sh" "$label" "$TARGET"
if [[ -n "$others" ]]; then
  say "publishing the new manifest to the running nodes"
  admin manifest publish
fi
say "done: $label is part of the network; phones learn about it on their next connection"
