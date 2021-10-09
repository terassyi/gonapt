#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include "bpf_helpers.h"

#include "hook.h"

#define PORT_MIN 49152
#define PORT_MAX 65535

BPF_MAP_DEF(if_redirect) = {
	.map_type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 128,
};
BPF_MAP_ADD(if_redirect);

BPF_MAP_DEF(if_index) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 64,
};
BPF_MAP_ADD(if_index);

BPF_MAP_DEF(if_mac) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u8) * 6,
	.max_entries = 64,
};
BPF_MAP_ADD(if_mac);

BPF_MAP_DEF(if_addr) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 64,
};
BPF_MAP_ADD(if_mac);

BPF_MAP_DEF(entries) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u16),
	.value_size = sizeof(__u8) * 21,
	.max_entries = 1024,
};
BPF_MAP_ADD(entries);

BPF_MAP_DEF(peer_port) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u8) * 6,
	.value_size = sizeof(__u16),
	.max_entries = 1024,
};
BPF_MAP_ADD(peer_port);

BPF_MAP_DEF(port_peer) = {
	.map_type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u16),
	.value_size = sizeof(__u8) * 6,
	.max_entries = 1024,
};
BPF_MAP_ADD(port_peer);


BPF_MAP_DEF(xdpcap_hook) = {
	.map_type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 5,
};
BPF_MAP_ADD(xdpcap_hook);

struct arphdr {
	__u16 ar_hrd;
	__u16 ar_pro;
	__u8 ar_hln;
	__u8 ar_pln;
	__u16 ar_op;
	__u8 ar_sha[ETH_ALEN];
	__u8 ar_sip[4];
	__u8 ar_tha[ETH_ALEN];
	__u8 ar_tip[4];
};

struct peer {
	__u32 addr;
	__u16 port;
};

struct entry {
	__u32 addr;
	__u16 port;
	__u8 protocol;
	__u8 mac_addr[6];
	__u64 timespamp;
};

__u16 alloc_port();

static inline __u16 checksum(__u16 *buf, __u32 bufsize) {
	__u32 sum = 0;
	while (bufsize > 1) {
		sum += *buf;
		buf++;
		bufsize -= 2;
	}
	if (bufsize == 1) {
		sum += *(__u8 *)buf;
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

static inline __u16 checksum2(__u8 *data1, int len1, __u8 *data2, int len2) {
	__u32 sum = 0;
	__u16 *ptr;
	int c;

	ptr = (__u16 *)data1;

	for (c = len1; c > 1; c -= 2) {
		sum += (*ptr);
		if (sum & 0x80000000) {
			sum = (sum & 0xffff) + (sum >> 16);
		}
		ptr++;
	}

	if (c == 1) {
		__u16 val;
		val = ((*ptr) << 8) + (*data2);
		sum += val;
		if (sum & 0x80000000) {
			sum = (sum & 0xffff) + (sum >> 16);
		}
		ptr = (__u16 *)(data2 + 1);
		len2--;
	} else {
		ptr = (__u16 *)data2;
	}

	for (c = len2; c > 1; c -= 2) {
		sum += (*ptr);
		if (sum & 0x80000000) {
			sum = (sum & 0xffff) + (sum >> 16);
		}
		ptr++;
	}

	if (c == 1) {
		__u16 val = 0;
		__builtin_memcpy(&val, ptr, sizeof(__u8));
		sum += val;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

static inline __u16 update_csum_u16(__u16 old_sum, __u16 old_data, __u16 new_data) {
	__u32 new_sum = old_sum - ~old_data - new_data;
	bpf_printk("new_sum %x", new_sum);
	return new_sum;
}

static inline int proxy_arp(struct arphdr *arp, struct ethhdr *eth, __u8 *mac_addr, __u32 *global_addr) {
	if (arp->ar_hrd != 0x0100 || arp->ar_pro != 0x08) {
		return XDP_PASS;
	}
	if (arp->ar_op != 0x100) {
		return XDP_PASS;
	}
	// build reply
	arp->ar_op = 0x0200;
	arp->ar_hrd = 0x0100;
	arp->ar_pro = 0x08;
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;
	__builtin_memcpy(arp->ar_tha, arp->ar_sha, ETH_ALEN);
	__builtin_memcpy(arp->ar_sha, mac_addr, ETH_ALEN);
	__builtin_memcpy(global_addr, arp->ar_tip, 4);
	__builtin_memcpy(arp->ar_tip, arp->ar_sip, 4);
	__builtin_memcpy(arp->ar_sip, global_addr, 4);

	__builtin_memcpy(eth->h_dest, arp->ar_tha, ETH_ALEN);
	__builtin_memcpy(eth->h_source, mac_addr, ETH_ALEN);
	return XDP_TX;
}

static inline int lookup_route_table(struct xdp_md *ctx, struct bpf_fib_lookup *fib_params, struct iphdr *ip, __u32 ifindex) {
	__builtin_memset(fib_params, 0, sizeof(*fib_params));
	fib_params->family = AF_INET;
	fib_params->ipv4_src = ip->saddr;
	fib_params->ipv4_dst = ip->daddr;
	fib_params->ifindex = ifindex;
	int rc = bpf_fib_lookup(ctx, fib_params, sizeof(*fib_params), 0);
	if ((rc != BPF_FIB_LKUP_RET_SUCCESS) && (rc != BPF_FIB_LKUP_RET_NO_NEIGH)) {
		bpf_printk("fib lookup failed.");
		return -1;
	} else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
		bpf_printk("fib lookup result is no neigh.");
		return -1;
	}
	return 0;
}

static inline __u16 lookup_entry(struct peer p) {
	__u16 alloced_ident = 0;
	__u16 *res = bpf_map_lookup_elem(&peer_port, &p);
	if (!res) {
		// new peer
		alloced_ident = alloc_port();
		if (bpf_map_update_elem(&peer_port, &p, &alloced_ident, 0) != 0) {
			bpf_printk("failed to register.");
		}
	} else {
		// already registered.
		alloced_ident = *res;
	}
	return alloced_ident;
}

SEC("xdp")
int nat_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
	__u32 ingress_ifindex = ctx->ingress_ifindex;
	__u32 in_key = 0;
	__u32 out_key = 1;
	__u32 *in_ifindex = bpf_map_lookup_elem(&if_index, &in_key);
	__u32 *out_ifindex = bpf_map_lookup_elem(&if_index, &out_key);
	if (!in_ifindex || !out_ifindex) {
		return XDP_PASS;
	}
	__u32 *in = bpf_map_lookup_elem(&if_redirect, in_ifindex);
	__u32 *out = bpf_map_lookup_elem(&if_redirect, out_ifindex);
	if (!in || !out) {
		bpf_printk("failed to get from if_redirect");
		return XDP_PASS;
	}
	bpf_printk("in = %d out = %d", *in, *out);

	__u8 *in_mac = bpf_map_lookup_elem(&if_mac, in_ifindex);
	__u8 *out_mac = bpf_map_lookup_elem(&if_mac, out_ifindex);
	if (!in_mac || !out_mac) {
		bpf_printk("failed to get in or out mac addr.");
		return XDP_PASS;
	}
	__u32 *global_addr = bpf_map_lookup_elem(&if_addr, out_ifindex);
	if (!global_addr) {
		bpf_printk("failed to get global ip addr.");
		return XDP_PASS;
	}

	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end) {
		return XDP_DROP;
	}
	if (eth->h_proto == 0x0608) {
		// arp
		bpf_printk("arp");
		// proxy arp handle
		struct arphdr *arp = data;
		if (data + sizeof(*arp) > data_end) {
			return XDP_DROP;
		}
		if (ingress_ifindex != *in_ifindex) {
			return XDP_PASS;
		}
		return proxy_arp(arp, eth,in_mac, global_addr);
	}
	if (eth->h_proto != 0x08U) {
		// not ipv4
		return XDP_PASS;
	}
	data += sizeof(*eth);
	struct iphdr *ip = data;
	if (data + sizeof(*ip) > data_end) {
		return XDP_DROP;
	}
	data += sizeof(*ip);
	if (ingress_ifindex == *in_ifindex) {
		// in
		// lookup route table
		struct bpf_fib_lookup fib_params;
		if (lookup_route_table(ctx, &fib_params, ip, ingress_ifindex) != 0) {
			return XDP_PASS;
		}

		// handle ip packet
		if (ip->protocol == 0x01) {
			// icmp
			struct icmphdr *icmp = data;
			if (data + sizeof(*icmp) > data_end) {
				return XDP_DROP;
			}
			if (icmp->type == 0 || icmp->type == 8) {
				// echo request or reply
				__u16 ident = icmp->un.echo.id;
				struct peer p;
				p.addr = ip->saddr;
				p.port = ident;
				__u16 alloced_ident = lookup_entry(p);
				// change ident field
				__u16 old_ident = icmp->un.echo.id;
				icmp->un.echo.id = htons(alloced_ident);
				// icmp->checksum = 0;
				__u32 new = ~(__u32)ntohs(icmp->checksum) + ~(__u32)ntohs(old_ident) + (__u32)alloced_ident;
				new = ~new;
				if (new > 0xffff0000) {
					new = (new & 0xffff) - 2;
					bpf_printk("->");
				} else {
					new--;
				}
				icmp->checksum = htons((__u16)new);
				bpf_printk("icmp checksum new = %x", new);
				// icmp->checksum = ()
				// icmp->checksum = update_csum_u16(icmp->checksum, old_ident, htons(alloced_ident));
				// change ip field
				ip->saddr = *global_addr;
				ip->check = 0;
				ip->check = checksum((__u16 *)ip, sizeof(*ip));

				struct entry ent;
				__builtin_memset(&ent, 0, sizeof(ent));
				ent.addr = p.addr;
				ent.port = p.port;
				ent.protocol = ip->protocol;
				__builtin_memcpy(&ent.mac_addr, eth->h_source, 6);
				ent.timespamp = bpf_ktime_get_ns();
				if (bpf_map_update_elem(&entries, &alloced_ident, &ent, 0) != 0) {
					bpf_printk("failed to update entries.");
					return XDP_PASS;
				}

				__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
				__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

				// bpf_printk("dmac %x:%x", eth->h_dest[0], eth->h_dest[5]);
				// bpf_printk("smac %x:%x", eth->h_source[0], eth->h_source[5]);
				// bpf_printk("ip src %d", ip->saddr);
				// bpf_printk("sent from global interface(%d).", *out_ifindex);
				return bpf_redirect_map(&if_redirect, *out_ifindex, 0);
				// return xdpcap_exit(ctx, &xdpcap_hook, action);
				// return bpf_redirect_map(&if_redirect, *out_ifindex, 0);
				// bpf_printk("action %d", action);
				// return action;
			}
			bpf_printk("only handle icmp echo");
			return XDP_PASS;

		} else if (ip->protocol == 0x06) {
			// tcp
			struct tcphdr *tcp = data;
			if (data + sizeof(*tcp) > data_end) {
				return XDP_DROP;
			}
			// struct peer p;
			// p.addr = ip->saddr;
			// p.port = tcp->source;
			// if (bpf_map_lookup_elem(&peer_port, &p) != 0) {
			// 	// already registered.
			// 	bpf_printk("peer already registered.");
			// } else {
			// 	// new peer
			// 	__u16 port = alloc_port();
			// 	if (bpf_map_update_elem(&peer_port, &p, &port, 0) != 0) {
			// 		bpf_printk("failed to register.");
			// 	}
			// }
			bpf_printk("tcp");
			__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
			__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
			return bpf_redirect_map(&if_redirect, *out_ifindex, 0);
			// return xdpcap_exit(ctx, &xdpcap_hook, action);

		} else if (ip->protocol == 0x11) {
			// udp
			struct udphdr *udp = data;
			if (data + sizeof(*udp) > data_end) {
				return XDP_DROP;
			}
			struct peer p;
			p.addr = ip->saddr;
			p.port = udp->uh_sport;
			if (bpf_map_lookup_elem(&peer_port, &p) != 0) {
				// already registered.
				bpf_printk("peer already registered.");
			} else {
				// new peer
				__u16 port = alloc_port();
				if (bpf_map_update_elem(&peer_port, &p, &port, 0) != 0) {
					bpf_printk("failed to register.");
				}
			}
			bpf_printk("udp");
		} else {
			return XDP_PASS;
		}

	} else {
		// out
		if (ip->protocol == 0x01) {
			// icmp
			struct icmphdr *icmp = data;
			if (data + sizeof(*icmp) > data_end) {
				return XDP_DROP;
			}
			if (icmp->type == 0 || icmp->type == 8) {
				// echo request or reply
				__u16 ident = ntohs(icmp->un.echo.id);
				__u8 *res = bpf_map_lookup_elem(&entries, &ident);
				if (!res) {
					bpf_printk("peer infomation is not registered.");
					return XDP_PASS;
				}
				struct entry *ent = (void *)res;
				// change ident field
				__u16 old_ident = icmp->un.echo.id;
				icmp->un.echo.id = htons(ent->port);
				// icmp->checksum = 0;
				__u32 new = ~(__u32)ntohs(icmp->checksum) + ~(__u32)ntohs(old_ident) + (__u32)ent->port;
				new = ~new;
				if (new > 0xffff0000) {
					new = (new & 0xffff) - 2;
				} else {
					new--;
				}
				icmp->checksum = htons((__u16)new);
				bpf_printk("icmp checksum new = %x", new);
				// icmp->checksum = ()
				// icmp->checksum = update_csum_u16(icmp->checksum, old_ident, htons(alloced_ident));
				// change ip field
				ip->daddr = ent->addr;
				ip->check = 0;
				ip->check = checksum((__u16 *)ip, sizeof(*ip));

				__builtin_memcpy(eth->h_source, out_mac, ETH_ALEN);
				__builtin_memcpy(eth->h_dest, ent->mac_addr, ETH_ALEN);
				bpf_printk("out dmac %x:%x", eth->h_dest[0], eth->h_dest[5]);
				bpf_printk("out smac %x:%x", eth->h_source[0], eth->h_source[5]);
				// bpf_printk("ip src %d", ip->saddr);
				// bpf_printk("sent from global interface(%d).", *out_ifindex);
				
				return bpf_redirect_map(&if_redirect, *in_ifindex, 0);
			}

		} else if (ip->protocol == 0x06) {
			// tcp
		} else if (ip->protocol == 0x11) {
			// udp
		} else {
			return XDP_PASS;
		}

	}
	bpf_printk("pass to end.");
	return XDP_PASS;
}

__u16 alloc_port() {
	__u16 port = 0;
	for (int i = 0; i < 10; i++) {
		port = PORT_MIN + (__u16)((__u16)bpf_get_prandom_u32() * (PORT_MAX - PORT_MIN + 1) / (PORT_MAX + 1));
		if (bpf_map_lookup_elem(&entries, &port) == 0) {
			break;
		}
	}
	return port;
}

char __license[] SEC("license") = "GPL";
