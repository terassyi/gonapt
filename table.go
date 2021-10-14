package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

type peer struct {
	addr net.IP
	port uint16
}

type entry struct {
	global uint16
	addr net.IP
	port uint16
	protocol uint8
	flag uint8
	macAddr []byte // 6 byte
	timestamp uint64
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

func (p *peer) Bytes() []byte {
	b := []byte(p.addr)
	c := make([]byte, 2)
	binary.BigEndian.PutUint16(c, p.port)
	return append(b, c...)

}

func entryFromBytes(data [22]byte) (*entry, error) {
	e := &entry{}
	e.addr = net.IP(data[:4])
	e.port = (uint16(data[4]) << 8 + uint16(data[5]))
	e.protocol = uint8(data[6])
	e.flag = uint8(data[7])
	// wip: flag allocation changed.
	e.macAddr = data[8:14]
	e.timestamp = binary.BigEndian.Uint64(data[14:])
	return e, nil
}

func (e *entry) String() string {
	macAddrStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", e.macAddr[0], e.macAddr[1], e.macAddr[2], e.macAddr[3], e.macAddr[4], e.macAddr[5])
	tcpState := ""
	if e.protocol == 0x06 {
		tcpState = fmt.Sprintf("tcp_state=%s", tcpStateString(e.flag))
	}
	return fmt.Sprintf("global=%d peer=%s:%d mac_addr=%s proto=%4s timestamp=%v %v", e.global, e.addr, e.port, macAddrStr, protoString(e.protocol), e.timestamp, tcpState)

}

func protoString(protocol uint8) string {
	switch protocol {
	case 0x01:
		return "ICMP"
	case 0x06:
		return "TCP"
	case 0x11:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}
