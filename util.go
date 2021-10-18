package main

import (
	"encoding/binary"
	"net"
	"os"
)

func putUint32ToUint64(a, b uint32) uint64 {
	return uint64(a) << 32 | uint64(b)
}

func ipv4ToUint32Big(addr net.IP) uint32 {
	return binary.BigEndian.Uint32(addr.To4())
}

func ipv4ToUint32Little(addr net.IP) uint32 {
	return binary.LittleEndian.Uint32(addr.To4())
}

func toLittleEndian(big []byte) []byte {
	li := make([]byte, len(big))
	for i, b := range big {
		li[len(big) - i - 1] = b
	}
	return li
}

func getPid() int {
	return os.Getpid()
}
