#!/bin/bash

sudo ip link set dev ens5 mtu 3498
sudo ip link set dev ens6 mtu 3498
sudo ethtool -L ens5 combined 1
sudo ethtool -L ens6 combined 1

