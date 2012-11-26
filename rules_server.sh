#!/bin/sh
TARGET=YOUR_REMOTE_IP
PORT=1194
L=30000
R=40000
iptables -t mangle -F
iptables -t mangle -A PREROUTING -d $TARGET -j NFQUEUE --queue-num 2012 --queue-bypass
iptables -t mangle -A POSTROUTING -s $TARGET -j NFQUEUE --queue-num 2013 --queue-bypass
./happy server $PORT $L $R
