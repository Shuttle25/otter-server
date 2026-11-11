#!/usr/bin/env bash
# Disposable Debian 12 VM for deploy tests. Usage: vm.sh start | stop | ssh [cmd...]
set -euo pipefail
cd "$(dirname "$0")/../.."
VM=.vm; CACHE="$HOME/.cache/otter-vm"
BASE_URL=https://cloud.debian.org/images/cloud/bookworm/latest
IMG=debian-12-genericcloud-amd64.qcow2
SSH=(ssh -p 2222 -i "$VM/id" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 root@127.0.0.1)
case "${1:-}" in
start)
  mkdir -p "$CACHE" "$VM/seed"
  if [[ ! -f "$CACHE/$IMG" ]]; then
    echo "==> downloading $IMG (~400 MB, once)"
    curl -fL -o "$CACHE/$IMG.part" "$BASE_URL/$IMG"
    curl -fsL -o "$CACHE/SHA512SUMS" "$BASE_URL/SHA512SUMS"
    (cd "$CACHE" && grep " $IMG\$" SHA512SUMS | sed "s/$IMG/$IMG.part/" | sha512sum -c --quiet)
    mv "$CACHE/$IMG.part" "$CACHE/$IMG"
  fi
  "$0" stop
  qemu-img create -q -f qcow2 -b "$CACHE/$IMG" -F qcow2 "$VM/disk.qcow2" 8G
  [[ -f "$VM/id" ]] || ssh-keygen -q -t ed25519 -N '' -f "$VM/id"
  cat > "$VM/seed/user-data" <<UD
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys: ["$(cat "$VM/id.pub")"]
UD
  printf 'instance-id: otter-e2e-%s\nlocal-hostname: otter-e2e\n' "$(date +%s)" > "$VM/seed/meta-data"
  # NoCloud seed as a small vfat disk labelled CIDATA (an HTTP seed via SMBIOS fell back to DataSourceNone on 22.4)
  rm -f "$VM/seed.img"; truncate -s 2M "$VM/seed.img"
  mkfs.vfat -n CIDATA "$VM/seed.img" >/dev/null
  mcopy -i "$VM/seed.img" "$VM/seed/user-data" "$VM/seed/meta-data" ::
  qemu-system-x86_64 -enable-kvm -cpu host -m 1024 -smp 2 -display none -daemonize -pidfile "$PWD/$VM/qemu.pid" \
    -drive file="$VM/disk.qcow2",if=virtio -drive file="$VM/seed.img",if=virtio,format=raw \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:27443-:27443 \
    -device virtio-net-pci,netdev=n0 -serial file:"$VM/console.log"
  echo "==> waiting for SSH"
  for _ in $(seq 120); do "${SSH[@]}" true 2>/dev/null && { echo "==> VM ready"; exit 0; }; sleep 2; done
  echo "VM did not come up (console: $VM/console.log)" >&2; tail -n 20 "$VM/console.log" >&2 || true; exit 1 ;;
stop)
  for p in qemu; do
    if [[ -f "$VM/$p.pid" ]]; then kill "$(cat "$VM/$p.pid")" 2>/dev/null || true; rm -f "$VM/$p.pid"; fi
  done
  rm -f "$VM/disk.qcow2" "$VM/seed.img" ;;
ssh) shift; exec "${SSH[@]}" "$@" ;;
*) echo "usage: vm.sh start|stop|ssh [cmd]" >&2; exit 2 ;;
esac
