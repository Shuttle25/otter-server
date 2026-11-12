#!/usr/bin/env bash
# Disposable Debian 12 VM for deploy tests. Usage: [OTTER_VM=name OTTER_VM_SSH=port OTTER_VM_WSS=port] vm.sh start | stop | ssh [cmd...]
set -euo pipefail
cd "$(dirname "$0")/../.."
NAME=${OTTER_VM:-vm}; SSH_PORT=${OTTER_VM_SSH:-2222}; WSS_PORT=${OTTER_VM_WSS:-27443}
VM=.vm; RUN=".vm/run-$NAME"; CACHE="$HOME/.cache/otter-vm"   # the SSH key is shared, the rest is per instance
BASE_URL=https://cloud.debian.org/images/cloud/bookworm/latest
IMG=debian-12-genericcloud-amd64.qcow2
SSH=(ssh -p "$SSH_PORT" -i "$VM/id" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 root@127.0.0.1)
case "${1:-}" in
start)
  mkdir -p "$CACHE" "$RUN/seed"
  if [[ ! -f "$CACHE/$IMG" ]]; then
    echo "==> downloading $IMG (~400 MB, once)"
    curl -fL -o "$CACHE/$IMG.part" "$BASE_URL/$IMG"
    curl -fsL -o "$CACHE/SHA512SUMS" "$BASE_URL/SHA512SUMS"
    (cd "$CACHE" && grep " $IMG\$" SHA512SUMS | sed "s/$IMG/$IMG.part/" | sha512sum -c --quiet)
    mv "$CACHE/$IMG.part" "$CACHE/$IMG"
  fi
  "$0" stop
  qemu-img create -q -f qcow2 -b "$CACHE/$IMG" -F qcow2 "$RUN/disk.qcow2" 8G
  [[ -f "$VM/id" ]] || ssh-keygen -q -t ed25519 -N '' -f "$VM/id"
  cat > "$RUN/seed/user-data" <<UD
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys: ["$(cat "$VM/id.pub")"]
UD
  printf 'instance-id: otter-%s-%s\nlocal-hostname: otter-%s\n' "$NAME" "$(date +%s)" "$NAME" > "$RUN/seed/meta-data"
  # NoCloud seed as a small vfat disk labelled CIDATA (an HTTP seed via SMBIOS fell back to DataSourceNone on 22.4)
  rm -f "$RUN/seed.img"; truncate -s 2M "$RUN/seed.img"
  mkfs.vfat -n CIDATA "$RUN/seed.img" >/dev/null
  mcopy -i "$RUN/seed.img" "$RUN/seed/user-data" "$RUN/seed/meta-data" ::
  qemu-system-x86_64 -enable-kvm -cpu host -m 1024 -smp 2 -display none -daemonize -pidfile "$PWD/$RUN/qemu.pid" \
    -drive file="$RUN/disk.qcow2",if=virtio -drive file="$RUN/seed.img",if=virtio,format=raw \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$WSS_PORT-:$WSS_PORT \
    -device virtio-net-pci,netdev=n0 -serial file:"$RUN/console.log"
  echo "==> waiting for SSH"
  for _ in $(seq 120); do "${SSH[@]}" true 2>/dev/null && { echo "==> VM ready"; exit 0; }; sleep 2; done
  echo "VM did not come up (console: $RUN/console.log)" >&2; tail -n 20 "$RUN/console.log" >&2 || true; exit 1 ;;
stop)
  if [[ -f "$RUN/qemu.pid" ]]; then kill "$(cat "$RUN/qemu.pid")" 2>/dev/null || true; rm -f "$RUN/qemu.pid"; fi
  rm -f "$RUN/disk.qcow2" "$RUN/seed.img" ;;
ssh) shift; exec "${SSH[@]}" "$@" ;;
*) echo "usage: vm.sh start|stop|ssh [cmd]" >&2; exit 2 ;;
esac
