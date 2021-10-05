package main

import (
	"net"
	"testing"
)

func TestPeerFromBytes(t *testing.T) {
	peerData := [6]byte{10, 0, 0, 1, 213, 253}
	p := peerFromBytes(peerData)
	if p.addr[0] != net.IP(peerData[:4])[0] || p.addr[3] != peerData[:4][3] {
		t.Fatalf("wanted 10.0.0.3 : actual %s", p.addr)
	}
	if p.port != ((213 << 8) + 253) {
		t.Fatalf("wanted 54781: actual %d", p.port)
	}
}
