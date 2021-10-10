#!/bin/bash

BUILD="build"
CLEAN="clean"

if [ "$BUILD" = "$1" ]; then
	echo "creating hosts"
	sudo ip netns add router # router
	sudo ip netns add srv # service in wan
	sudo ip netns add host1 # host1 in lan 
	sudo ip netns add host2 # host2 in lan 
	sudo ip netns add host3 # host3 in lan 

	echo "creating cables"
	sudo ip link add h1-v0 type veth peer br0-v0
	sudo ip link add h2-v0 type veth peer br0-v1
	sudo ip link add h3-v0 type veth peer br0-v2
	sudo ip link add np-l type veth peer br0-v3
	sudo ip link add br0 type bridge
	sudo ip link add np-w type veth peer r-0
	sudo ip link add srv-v0 type veth peer r-1

	echo "setting hosts"
	sudo ip link set h1-v0 netns host1
	sudo ip link set h2-v0 netns host2
	sudo ip link set h3-v0 netns host3
	sudo ip link set r-0 netns router
	sudo ip link set r-1 netns router
	sudo ip link set srv-v0 netns srv

	echo "setting bridge"
	sudo ip link set dev br0-v0 master br0
	sudo ip link set dev br0-v1 master br0
	sudo ip link set dev br0-v2 master br0
	sudo ip link set dev br0-v3 master br0

	echo "setting addresses"
	sudo ip netns exec host1 ip addr add 10.0.0.1/24 dev h1-v0
	sudo ip netns exec host2 ip addr add 10.0.0.2/24 dev h2-v0
	sudo ip netns exec host3 ip addr add 10.0.0.3/24 dev h3-v0
	sudo ip addr add 10.0.0.254/24 dev np-l
	sudo ip addr add 138.76.28.4/24 dev np-w
	sudo ip netns exec router ip addr add 138.76.28.1/24 dev r-0
	sudo ip netns exec router ip addr add 138.76.29.254/24 dev r-1
	sudo ip netns exec srv ip addr add 138.76.29.7/24 dev srv-v0 

	echo "setting up"
	sudo ip netns exec host1 ip link set up h1-v0
	sudo ip netns exec host1 ip link set up lo
	sudo ip netns exec host2 ip link set up h2-v0
	sudo ip netns exec host2 ip link set up lo
	sudo ip netns exec host3 ip link set up h3-v0
	sudo ip netns exec host3 ip link set up lo
	sudo ip link set up np-l
	sudo ip link set up np-w
	sudo ip link set up br0
	sudo ip link set up br0-v0
	sudo ip link set up br0-v1
	sudo ip link set up br0-v2
	sudo ip link set up br0-v3
	sudo ip link set up lo
	sudo ip netns exec srv ip link set up srv-v0
	sudo ip netns exec srv ip link set up lo
	sudo ip netns exec router ip link set up r-0
	sudo ip netns exec router ip link set up r-1
	sudo ip netns exec router ip link set up lo

	echo "setting routes"
	sudo ip netns exec host1 ip route add default via 10.0.0.254
	sudo ip netns exec host2 ip route add default via 10.0.0.254
	sudo ip netns exec host3 ip route add default via 10.0.0.254
	sudo ip route add 138.76.29.0/24 via 138.76.28.1 dev np-w
	sudo ip netns exec router ip route add default via 138.76.29.254
	sudo ip netns exec srv ip route add default via 138.76.29.254


elif [ "$CLEAN" = "$1" ]; then
	sudo ip link del np-w
	sudo ip link del np-l
	sudo ip link del br0
	sudo ip link del br0-v0
	sudo ip link del br0-v1
	sudo ip link del br0-v2
	sudo ip route del 138.76.29.0/24 via 138.76.28.1 dev np-w
	sudo ip netns del srv
	sudo ip netns del router
	sudo ip netns del host1
	sudo ip netns del host2
	sudo ip netns del host3
else
	echo "help:"
	echo "	build: build a network to test with netns"
	echo "	clean: clean up a network"
fi


