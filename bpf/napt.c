#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include "bpf_helpers.h"
#include "csum_helpers.h"

#include "header/bpf_helpers.h"
#include "tcp.h"
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
	.value_size = sizeof(__u8) * 22,
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
	__u8 flag;
	__u8 mac_addr[6];
	__u64 timestamp;
};

__u16 alloc_port();

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

static inline __u16 lookup_entry_key(struct peer p) {
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

static inline int lookup_entry(__u16 *key, struct entry *ent) {
	__u8 *res = bpf_map_lookup_elem(&entries, key);
	if (!res) {
		return -1;
	}
	ent = (void *)res;
	return 0;
}

static inline int update_entry(__u16 *key, struct peer p, __u8 protocol, __u8 *mac_addr, __u8 flag) {
	struct entry ent;
	__builtin_memset(&ent, 0, sizeof(ent));
	ent.addr = p.addr;
	ent.port = p.port;
	ent.protocol = protocol;
	__builtin_memcpy(&ent.mac_addr, mac_addr, ETH_ALEN);
	ent.timestamp = bpf_ktime_get_ns();
	ent.flag = flag;
	if (bpf_map_update_elem(&entries, key, &ent, 0) != 0) {
		bpf_printk("failed to update entries.");
		return -1;
	}
	return 0;
}

static inline int redirect(struct ethhdr *eth, __u8 *s_mac, __u8 *d_mac, __u32 ifindex) {
	__builtin_memcpy(eth->h_dest, d_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, s_mac, ETH_ALEN);
	return bpf_redirect_map(&if_redirect, ifindex, 0);

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
			if (icmp->type == 0 || icmp->type == 8 || (icmp->type > 12 && icmp->type < 19)) {
				// echo request or reply
				__u16 ident = icmp->un.echo.id;
				struct peer p;
				p.addr = ip->saddr;
				p.port = ident;
				__u16 alloced_ident = lookup_entry_key(p);
				// change ident field
				__u16 old_ident = icmp->un.echo.id;
				icmp->un.echo.id = htons(alloced_ident);
				icmp->checksum = ipv4_csum_update_u16(icmp->checksum, old_ident, htons(alloced_ident));
				// change ip field
				ip->saddr = *global_addr;
				ip->check = 0;
				ip->check = checksum((__u16 *)ip, sizeof(*ip));
				if (update_entry(&alloced_ident, p, ip->protocol, eth->h_source, 0) != 0) {
					return XDP_PASS;
				}
			}
			return redirect(eth, fib_params.smac, fib_params.dmac, *out_ifindex);

		} else if (ip->protocol == 0x06) {
			// tcp
			struct tcphdr *tcp = data;
			if (data + sizeof(*tcp) > data_end) {
				return XDP_DROP;
			}
			struct peer p;
			p.addr = ip->saddr;
			p.port = tcp->th_sport;
			__u16 alloced_port = lookup_entry_key(p);
			// update tcp checksum
			tcp->th_sum = ipv4_csum_update_u16(tcp->th_sum,tcp->th_sport, htons(alloced_port));
			tcp->th_sum = ipv4_csum_update_u32(tcp->th_sum, ip->saddr, *global_addr);
			// update tcp port
			tcp->th_sport = htons(alloced_port);
			// update ip field
			ip->check = ipv4_csum_update_u32(ip->check, ip->saddr, *global_addr);
			ip->saddr = *global_addr;
			// update tcp state
			__u8 tcp_state = 0;
			__u8 *res = bpf_map_lookup_elem(&entries, &alloced_port);
			if (!res) {
				tcp_state = (__u8)TCP_CLOSE;
			}
			struct entry *ent = (void *)res;
			if (tcp_state == 0) {
				tcp_state = ent->flag;
			}
			__u8 new_tcp_state = tcp_state_update(tcp_state, tcp->th_flags, 1);
			if (update_entry(&alloced_port, p, ip->protocol, eth->h_source, new_tcp_state) != 0) {
					return XDP_PASS;
			}
			return redirect(eth, fib_params.smac, fib_params.dmac, *out_ifindex);

		} else if (ip->protocol == 0x11) {
			// udp
			struct udphdr *udp = data;
			if (data + sizeof(*udp) > data_end) {
				return XDP_DROP;
			}
			struct peer p;
			p.addr = ip->saddr;
			p.port = udp->uh_sport;
			__u16 alloced_port = lookup_entry_key(p);
			// update udp checksum
			udp->uh_sum = ipv4_csum_update_u16(udp->uh_sum, udp->uh_sport, htons(alloced_port));
			udp->uh_sum = ipv4_csum_update_u32(udp->uh_sum, ip->saddr, *global_addr);
			// udp update port
			udp->uh_sport = htons(alloced_port);
			// ip checksum update
			ip->saddr = *global_addr;
			ip->check = 0;
			ip->check = checksum((__u16 *)ip, sizeof(*ip));
			if (update_entry(&alloced_port, p, ip->protocol, eth->h_source, 0) != 0) {
				return XDP_PASS;
			}
			return redirect(eth, fib_params.smac, fib_params.dmac, *out_ifindex);
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
			if (icmp->type == 0 || icmp->type == 8 || (icmp->type > 12 && icmp->type < 19)) {
				// echo request or reply
				__u16 ident = ntohs(icmp->un.echo.id);
				__u8 *res = bpf_map_lookup_elem(&entries, &ident);
				if (!res) {
					return XDP_PASS;
				}
				struct entry *ent = (void *)res;
				// change ident field
				__u16 old_ident = icmp->un.echo.id;
				icmp->un.echo.id = ent->port;
				icmp->checksum = ipv4_csum_update_u16(icmp->checksum, old_ident, ent->port);
				ip->daddr = ent->addr;
				ip->check = 0;
				__u64 sum = 0;
				ipv4_csum_inline(ip, &sum);
				ip->check = (__u16)sum;

				return redirect(eth, out_mac, ent->mac_addr, *in_ifindex);
			} else if ((icmp->type > 2 && icmp->type < 6) || (icmp->type > 10 && icmp->type < 13)) {
				data += 8;
				struct iphdr *prev_ip = data;
				if (data + sizeof(*prev_ip) > data_end) {
					return XDP_PASS;
				}
				bpf_printk("icmp prev_ip proto %d", prev_ip->protocol);
				// tcp or udp
				data += sizeof(*prev_ip);
				if (prev_ip->protocol == 0x06) {
					struct tcphdr *prev_tcp = data;
					if (data + sizeof(*prev_tcp) > data_end) {
						return XDP_PASS;
					}
					__u16 prev_source_port = ntohs(prev_tcp->th_sport);
					__u8 *res = bpf_map_lookup_elem(&entries, &prev_source_port);
					if (!res) {
						return XDP_PASS;
					}
					bpf_printk("prev_tcp");
					struct entry *ent = (void *)res;
					icmp->checksum = ipv4_csum_update_u16(icmp->checksum, prev_tcp->th_sport, ent->port);
					icmp->checksum = ipv4_csum_update_u32(icmp->checksum, prev_ip->saddr, ent->addr);
					prev_tcp->th_sport = ent->port;
					prev_ip->saddr = ent->addr;
					ip->daddr = ent->addr;
					ip->check = 0;
					__u64 sum = 0;
					ipv4_csum_inline(ip, &sum);
					ip->check = (__u16)sum;
					return redirect(eth, out_mac, ent->mac_addr, *in_ifindex);


				} else if (prev_ip->protocol == 0x11) {
					struct udphdr *prev_udp = data;
					if (data + sizeof(*prev_udp) > data_end) {
						return XDP_PASS;
					}
					__u16 prev_source_port = ntohs(prev_udp->uh_sport);
					__u8 *res = bpf_map_lookup_elem(&entries, &prev_source_port);
					if (!res) {
						return XDP_PASS;
					}
					bpf_printk("prev_udp port");
					struct entry *ent = (void *)res;
					icmp->checksum = ipv4_csum_update_u16(icmp->checksum, prev_udp->uh_sport, ent->port);
					icmp->checksum = ipv4_csum_update_u32(icmp->checksum, prev_ip->saddr, ent->addr);
					prev_udp->uh_sport = ent->port;
					prev_ip->saddr = ent->addr;
					ip->daddr = ent->addr;
					ip->check = 0;
					__u64 sum = 0;
					ipv4_csum_inline(ip, &sum);
					ip->check = (__u16)sum;
					return redirect(eth, out_mac, ent->mac_addr, *in_ifindex);

				} else {
					return XDP_PASS;
				}
			}

		} else if (ip->protocol == 0x06) {
			// tcp
			struct tcphdr *tcp = data;
			if (data + sizeof(*tcp) > data_end) {
				return XDP_DROP;
			}
			__u16 dest_port = ntohs(tcp->th_dport);
			__u8 *res = bpf_map_lookup_elem(&entries, &dest_port);
			if (!res) {
				return XDP_PASS;
			}
			struct entry *ent = (void *)res;
			__u8 tcp_state = tcp_state_update(ent->flag, tcp->th_flags, 0);
			// update tcp checksum
			tcp->th_sum = ipv4_csum_update_u16(tcp->th_sum, tcp->th_dport, ent->port);
			tcp->th_sum = ipv4_csum_update_u32(tcp->th_sum, ip->daddr, ent->addr);
			// update dest port
			tcp->th_dport = ent->port;
			// update ip checksum
			ip->check = ipv4_csum_update_u32(ip->check, ip->daddr, ent->addr);
			// update ip dest
			ip->daddr = ent->addr;
			struct peer p;
			p.addr = ent->addr;
			p.port = ent->port;
			if (update_entry(&dest_port, p, ent->protocol, ent->mac_addr, tcp_state) != 0) {
				return XDP_PASS;
			}
			return redirect(eth, out_mac, ent->mac_addr, *in_ifindex);
		} else if (ip->protocol == 0x11) {
			// udp
			struct udphdr *udp = data;
			if (data + sizeof(*udp) > data_end) {
				return XDP_DROP;
			}
			__u16 dest_port = ntohs(udp->uh_dport);
			__u8 *res = bpf_map_lookup_elem(&entries, &dest_port);
			if (!res) {
				return XDP_PASS;
			}
			struct entry *ent = (void *)res;
			// update dest port
			udp->uh_dport = ent->port;
			// update ip dest
			__u32 old_addr = ip->daddr;
			ip->daddr = ent->addr;
			// update udp check
			udp->uh_sum = ipv4_csum_update_u16(udp->uh_sum, dest_port, udp->uh_dport);
			udp->uh_sum = ipv4_csum_update_u32(udp->uh_sum, old_addr, ip->daddr);
			// update ip checksum
			ip->check = ipv4_csum_update_u32(ip->check, old_addr, ip->daddr);
			return redirect(eth, out_mac, ent->mac_addr, *in_ifindex);
		} else {
			return XDP_PASS;
		}

	}
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
