package main

import "net"

type peer struct {
	addr net.IP
	port uint16
}

func peerFromBytes(data [6]byte) peer {
	// 0-3 bytes : ip addr
	// 4-5 bytes : port
	port := (uint16(data[4]) << 8) + uint16(data[5])
	return peer {
		addr: net.IP(data[:4]),
		port: port,
	}
}
