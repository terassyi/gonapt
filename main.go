package main

import (
	"fmt"
	"os"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang NaptProg ./bpf/napt.c -- -I./bpf/header

func main() {
	app := NewCommand()
	if err := app.Prepare(); err != nil {
		fmt.Println("failed to prepare gonapt")
		os.Exit(1)
	}
	if err := app.Run(); err != nil {
		fmt.Println("failed to run")
		os.Exit(1)
	}
}
