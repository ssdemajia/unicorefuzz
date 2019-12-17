#!/bin/sh
stty intr ^]
echo "[*] ctrl+c remapped to ctrl+] for host"

/home/ss/qemu-4.2.0/x86_64-softmmu/qemu-system-x86_64 -hda /home/ss/buildroot/output/images/rootfs.ext2 \
	-net nic -net user,hostfwd=tcp::8022-:22 \
	-m 4096 \
	-smp 1 \
	-s \
	-append "root=/dev/sda console=ttyS0 debug nokaslr quiet" \
	-serial stdio \
	-display none \
  	-kernel /home/ss/Downloads/linux-5.4.3/arch/x86/boot/bzImage \
#	-monitor telnet:127.0.0.1:1235,server,nowait
#	-enable-kvm \
# -s makes qemu listen on 1234
# -smp 1 sets it to single core
