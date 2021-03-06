package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

const (
	PORT_MIN uint32 = 49152
	PORT_MAX uint32 = 65535

	DEFAULT_TIMEOUT time.Duration = time.Second * 60
	DEFAULT_TCP_TIMEOUT time.Duration = time.Second * 60 * 60
	DEFAULT_TIMEOUT_HALF time.Duration = time.Second * 30
	DEFAULT_TIMEOUT_SHORT time.Duration = time.Second * 10
)

type Napt struct {
	in netlink.Link
	out netlink.Link
	global net.IP
	local net.IP
	localNet net.IPNet
	spec *ebpf.CollectionSpec
	collect *NaptCollect
	gcMap map[uint16]*gcEntry
	timeout time.Duration
	tcpTimeout time.Duration
	quitCh chan bool
	serverQuitCh chan bool
}

type gcEntry struct {
	mark int64
	timestamp uint64
}

type NaptCollect struct {
	Prog *ebpf.Program `ebpf:"nat_prog"`
	IfRedirectMap *ebpf.Map `ebpf:"if_redirect"`
	IfIndexMap *ebpf.Map `ebpf:"if_index"`
	IfMacMap *ebpf.Map `ebpf:"if_mac"`
	IfAddrMap *ebpf.Map `ebpf:"if_addr"`
	PeerPortMap *ebpf.Map `ebpf:"peer_port"`
	Entries *ebpf.Map `ebpf:"entries"`
	XdpcpHook *ebpf.Map `ebpf:"xdpcap_hook"`
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
	if err := initLog(); err != nil {
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
		gcMap: make(map[uint16]*gcEntry),
		timeout: DEFAULT_TIMEOUT_HALF,
		tcpTimeout: DEFAULT_TCP_TIMEOUT,
		quitCh: make(chan bool),
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
	gcTicker := time.NewTicker(time.Second * 1)
	fmt.Println("Go NAPT running...")
	fmt.Println("Press CTRL+C to exit.")
	for {
		select {
		case <-ticker.C:
			n.Check()
		case <-gcTicker.C:
			if err := n.GarbageCollection(); err != nil {
				fmt.Println(err)
			}
		case <-ctrlC:
			fmt.Println("detaching xdp program...")
			return n.Detach()
		}
	}
}

func (n *Napt) RunBackGround() error {
	fmt.Println("PID: ", getPid())
	if err := n.Attach(); err != nil {
		return err
	}
	if err := cleanup(); err != nil {
		return err
	}
	listener, err := net.Listen(protocol, addr)
	if err != nil {
		return err
	}
	gcTicker := time.NewTicker(time.Second * 1)
	go func() {
		for {
			select {
			case <-gcTicker.C:
				if err := n.GarbageCollection(); err != nil {
					log.Println(err)
				}
			case <-n.quitCh:
				if err := n.Detach(); err != nil {
					log.Println(err)
				}
			}
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
		}
		exit, err := n.handleConn(conn)
		if err != nil {
			log.Println(err)
		}
		if exit {
			time.Sleep(time.Second * 1)
			break
		}
	}
	return nil
}

func (n *Napt) Attach() error {
	if err := attach(n.collect.Prog, n.in); err != nil {
		return err
	}
	if err := attach(n.collect.Prog, n.out); err != nil {
		return err
	}
	// if err := n.collect.XdpcpHook.Pin("/sys/fs/bpf/napt"); err != nil {
	// 	return err
	// }
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
	if err := n.collect.IfRedirectMap.Put(uint32(n.in.Attrs().Index), uint32(n.in.Attrs().Index)); err != nil {
		return err
	}
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
	return nil
}

func (n *Napt) Check() error {
	var (
		key uint16
		value [22]byte
	)

	iter := n.collect.Entries.Iterate()
	for iter.Next(&key, &value) {
		entry, err := entryFromBytes(value)
		if err != nil {
			return err
		}
		entry.global = key
		fmt.Println(entry.String())
	}
	fmt.Println("finished iterating")
	return nil
}

func (n *Napt) GarbageCollection() error {
	var (
		key uint16
		value [22]byte
	)

	iter := n.collect.Entries.Iterate()
	for iter.Next(&key, &value) {
		entry, err := entryFromBytes(value)
		if err != nil {
			fmt.Println(err)
			return err
		}
		entry.global = key
		g, ok := n.gcMap[key]
		if !ok {
			n.gcMap[key] = &gcEntry {
				mark: 0,
				timestamp: entry.timestamp,
			}
			continue
		}

		if entry.timestamp == g.timestamp {
			g.mark++
		} else {
			g.mark = 0
		}
		if entry.protocol != 0x06 {
			if g.mark > int64(n.timeout.Seconds()) {
				delete(n.gcMap, key)
				if err := n.deleteEntry(key, peer{
					addr: entry.addr,
					port: entry.port,
				}); err != nil {
					return err
				}
			}
		} else {
			if entry.flag == TCP_CLOSE  || entry.flag == TCP_SYN_SENT {
				if g.mark > int64(n.timeout.Seconds()) {
					delete(n.gcMap, key)
					if err := n.deleteEntry(key, peer{
						addr: entry.addr,
						port: entry.port,
					}); err != nil {
						return err
					}
				}
			} else {
				if g.mark > int64(n.tcpTimeout.Seconds()) {
					delete(n.gcMap, key)
					if err := n.deleteEntry(key, peer{
						addr: entry.addr,
						port: entry.port,
					}); err != nil {
						return err
					}
				}
			}
		}
		g.timestamp = entry.timestamp
	}
	return nil
}

func (n *Napt) deleteEntry(key uint16, p peer) error {
	if err := n.collect.Entries.Delete(key); err != nil {
		return err
	}
	return n.collect.PeerPortMap.Delete(p.Bytes())
}

func attach(prog *ebpf.Program, dev netlink.Link) error {
	return netlink.LinkSetXdpFdWithFlags(dev, prog.FD(), nl.XDP_FLAGS_SKB_MODE)
	// return netlink.LinkSetXdpFd(dev, prog.FD())
}

func detach(dev netlink.Link) error {
	return netlink.LinkSetXdpFdWithFlags(dev, -1, nl.XDP_FLAGS_SKB_MODE)
}

func (n *Napt) lookupEntry() ([]tableEntry, error) {
	entries := make([]tableEntry, 0, 1024)
	var (
		key uint16
		value [22]byte
	)

	iter := n.collect.Entries.Iterate()
	for iter.Next(&key, &value) {
		entry, err := entryFromBytes(value)
		if err != nil {
			return nil, err
		}
		entry.global = key
		entries = append(entries, entry.toTableEntry())
	}
	return entries, nil
}
