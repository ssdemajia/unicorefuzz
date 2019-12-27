#!/bin/sh
brctl addbr br0
brctl addif br0 enp2s0
brctl stp br0 on
ifconfig enp2s0 0
dhclient br0
