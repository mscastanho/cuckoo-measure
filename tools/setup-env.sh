#!/usr/bin/env bash

# Script to configure the environment to send/receive
# packets from BPFabric

# Namespaces
NSCMD="ip netns exec"
NS0="ns0"
NS1="ns1"

# Interface 0
I0="nf0"
IP0="10.0.0.1"
MAC0="$(ip link show $I0 | grep link/ether | awk '{print $2}')"

# Interface 1
I1="nf1"
IP1="10.0.0.2"
MAC1="$(ip link show $I1 | grep link/ether | awk '{print $2}')"

# Create namespaces
ip netns add $NS0
ip netns add $NS1

# Attribute interfaces to corresponding namespace
ip link set dev $I0 netns $NS0
ip link set dev $I1 netns $NS1

# Set IP addresses
$NSCMD $NS0 ifconfig $I0 $IP0/24 up
$NSCMD $NS1 ifconfig $I1 $IP1/24 up

# Add static entries on ARP table
$NSCMD $NS0 arp -s $IP1 $MAC1
$NSCMD $NS1 arp -s $IP0 $MAC0