#!/bin/sh
qemu-system-x86_64 -drive file=../ARCH.img,if=virtio \
	-enable-kvm \
	-net nic -net user,hostfwd=tcp::8022-:22 \
	-m 4096 \
	-smp 4 \
  -cdrom /home/ss/ubuntu-18.04.3-live-server-amd64.iso \
  -boot d
