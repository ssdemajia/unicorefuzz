#!/bin/sh
stty intr ^]
echo "[*] ctrl+c remapped to ctrl+] for host"

/home/ss/qemu-4.2.0/i386-softmmu/qemu-system-i386 -hda /home/ss/MS-DOS.vmdk \
	-net nic -net user,hostfwd=tcp::8022-:22 \
	-m 2096 \
	-smp 1 \
	-s \
#	-monitor telnet:127.0.0.1:1235,server,nowait
#	-enable-kvm \
# -s makes qemu listen on 1234
# -smp 1 sets it to single core
