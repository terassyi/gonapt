package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

const (
	PORT_MIN uint32 = 49152
	PORT_MAX uint32 = 65535
)

type Napt struct {
	in netlink.Link
	out netlink.Link
	global net.IP
	local net.IP
	localNet net.IPNet
	spec *ebpf.CollectionSpec
	collect *NaptCollect
}

type NaptCollect struct {
	Prog *ebpf.Program `ebpf:"nat_prog"`
	IfRedirectMap *ebpf.Map `ebpf:"if_redirect"`
	IfIndexMap *ebpf.Map `ebpf:"if_index"`
	IfMacMap *ebpf.Map `ebpf:"if_mac"`
	IfAddrMap *ebpf.Map `ebpf:"if_addr"`
	PeerPortMap *ebpf.Map `ebpf:"peer_port"`
	PortPeerMap *ebpf.Map `ebpf:"port_peer"`
	Entries *ebpf.Map `ebpf:"entries"`
}

func newNapt(in, out, global, local string) (*Napt, error) {
	inL, err := netlink.LinkByName(in)
	if err != nil {
		return nil, err
	}
	outL, err := netlink.LinkByName(out)
	if err != nil {
		return nil, err
	}
	localAddr, localNet, err := net.ParseCIDR(local)
	var collect = &NaptCollect{}
	spec,err := LoadNaptProg()
	if err != nil {
		return nil, err
	}
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		return nil, err
	}
	return &Napt {
		in: inL,
		out: outL,
		global: net.ParseIP(global),
		local: localAddr,
		localNet: *localNet,
		spec: spec,
		collect: collect,
	}, nil
}

func (n *Napt) show() {
	fmt.Println("----- napt information -----")
	fmt.Printf("global address = %s\n", n.global)
	fmt.Printf("local address = %s\n", &n.localNet)
}

func (n *Napt) Run() error {
	if err := n.Attach(); err != nil {
		return err
	}
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	ticker := time.NewTicker(time.Second * 10)
	fmt.Println("Go NAPT running...")
	fmt.Println("Press CTRL+C to exit.")
	for {
		select {
		case <-ticker.C:
			n.Check()
		case <-ctrlC:
			fmt.Println("detaching xdp program...")
			return n.Detach()
		}
	}
}

func (n *Napt) Attach() error {
	if err := attach(n.collect.Prog, n.in); err != nil {
		return err
	}
	if err := attach(n.collect.Prog, n.out); err != nil {
		return err
	}
	return nil
}

func (n *Napt) Detach() error {
	if err := detach(n.in); err != nil {
		return err
	}
	if err := detach(n.out); err != nil {
		return err
	}
	return nil
}

func (n *Napt) Prepare() error {
	fmt.Println("aa")
	if err := n.collect.IfRedirectMap.Put(uint32(n.in.Attrs().Index), uint32(n.in.Attrs().Index)); err != nil {
		return err
	}
	fmt.Println("bb")
	if err := n.collect.IfRedirectMap.Put(uint32(n.out.Attrs().Index), uint32(n.out.Attrs().Index)); err != nil {
		return err
	}
	if err := n.collect.IfIndexMap.Put(uint32(0), uint32(n.in.Attrs().Index)); err != nil {
		return err
	}
	if err := n.collect.IfIndexMap.Put(uint32(1), uint32(n.out.Attrs().Index)); err != nil {
		return err
	}
	if err := n.collect.IfAddrMap.Put(uint32(n.out.Attrs().Index), ipv4ToUint32Little(n.global)); err != nil {
		return err
	}
	if err := n.collect.IfMacMap.Put(uint32(n.in.Attrs().Index), []byte(n.in.Attrs().HardwareAddr)); err != nil {
		return err
	}
	if err := n.collect.IfMacMap.Put(uint32(n.out.Attrs().Index), []byte(n.out.Attrs().HardwareAddr)); err != nil {
		return err
	}

	var (
		key uint32
		value uint32
	)
	iter := n.collect.IfRedirectMap.Iterate()
	for iter.Next(&key, &value) {
		fmt.Printf("key = %d value = %d\n", key, value)
	}

	return nil
}

func (n *Napt) Check() error {
	var (
		key [6]byte
		value uint16
	)

	iter := n.collect.PeerPortMap.Iterate()
	for iter.Next(&key, &value) {
		p := peerFromBytes(key)
		fmt.Printf("%s:%d => %d\n", p.addr, p.port, value)
	}
	fmt.Println("finished iterating")
	return nil
}

func attach(prog *ebpf.Program, dev netlink.Link) error {
	return netlink.LinkSetXdpFd(dev, prog.FD())
}

func detach(dev netlink.Link) error {
	return netlink.LinkSetXdpFd(dev, -1)
}
