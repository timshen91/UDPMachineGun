#!/bin/sh
TARGET=YOUR_REMOTE_IP
iptables -t mangle -F
iptables -t mangle -A PREROUTING -d $TARGET -p udp -j NFQUEUE --queue-num 2012 --queue-bypass
iptables -t mangle -A POSTROUTING -s $TARGET -p udp -j NFQUEUE --queue-num 2013 --queue-bypass
