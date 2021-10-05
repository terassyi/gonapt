package main

import (
	"flag"
	"fmt"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NaptProg ./bpf/napt.c -- -I./bpf/headers

func main() {
	var in, out, global, local string
	flag.StringVar(&in, "in","", "in(local) interface")
	flag.StringVar(&out, "out","", "out(global) interface")
	flag.StringVar(&global, "global", "", "global address")
	flag.StringVar(&local, "local", "", "local address and subnet")
	flag.Parse()

	napt, err := newNapt(in, out, global, local)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	if err := napt.Prepare(); err != nil {
		panic(err)
	}
	if err := napt.Run(); err != nil {
		panic(err)
	}
}
