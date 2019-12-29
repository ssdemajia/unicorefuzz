#!/bin/sh
echo "[*] set network bridge "
brctl addbr br0
echo "[*] add bridge: br0 "
brctl addif br0 enp2s0
echo "[*] set br0 with enp2s0"
brctl stp br0 on
echo "[*] br0 stp on"
ifconfig enp2s0 0
dhclient br0
echo "[*] dhcp br0"
