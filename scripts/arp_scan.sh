#!/bin/bash
# Double ping-sweep then dump ARP table.
# Two passes to catch devices with high latency or intermittent connectivity.
SUBNET="${1:-192.168.88}"

# Pass 1: fast parallel ping
for i in $(seq 1 254); do
    ping -c 1 -W 1 "$SUBNET.$i" >/dev/null 2>&1 &
done
wait

# Pass 2: retry to catch slow/intermittent devices
sleep 2
for i in $(seq 1 254); do
    ping -c 1 -W 1 "$SUBNET.$i" >/dev/null 2>&1 &
done
wait

# Dump ARP table filtered to subnet
arp -a | grep "$SUBNET"
