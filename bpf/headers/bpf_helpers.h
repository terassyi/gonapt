/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

/*
 * Note that bpf programs need to include either
 * vmlinux.h (auto-generated from BTF) or linux/types.h
 * in advance since bpf_helper_defs.h uses such types
 * as __u64.
 */
#include "bpf_helper_defs.h"
#include "common.h"

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

/*
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __always_inline
#define __always_inline __attribute__((always_inline))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif

/*
 * Helper macro to manipulate data structures
 */
#ifndef offsetof
#define offsetof(TYPE, MEMBER)  __builtin_offsetof(TYPE, MEMBER)
#endif
#ifndef container_of
#define container_of(ptr, type, member)				\
	({							\
		void *__mptr = (void *)(ptr);			\
		((type *)(__mptr - offsetof(type, member)));	\
	})
#endif

/*
 * Helper structure used by eBPF C program
 * to describe BPF map attributes to libbpf loader
 */
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

enum libbpf_pin_type {
	LIBBPF_PIN_NONE,
	/* PIN_BY_NAME: pin maps by name (in /sys/fs/bpf by default) */
	LIBBPF_PIN_BY_NAME,
};

enum libbpf_tristate {
	TRI_NO = 0,
	TRI_YES = 1,
	TRI_MODULE = 2,
};

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

// XDP metadata - basically data packet
// P.S. for some reason XDP programs uses 32bit pointers
struct xdp_md {
  u32 data;
  u32 data_end;
  u32 data_meta;
  /* Below access go through struct xdp_rxq_info */
  u32 ingress_ifindex; /* rxq->dev->ifindex */
  u32 rx_queue_index;  /* rxq->queue_index  */

  u32 egress_ifindex;  /* txq->dev->ifindex */
};

enum {
  BPF_FIB_LOOKUP_DIRECT  = (1U << 0),
  BPF_FIB_LOOKUP_OUTPUT  = (1U << 1),
};

enum {
  BPF_FIB_LKUP_RET_SUCCESS,      /* lookup successful */
  BPF_FIB_LKUP_RET_BLACKHOLE,    /* dest is blackholed; can be dropped */
  BPF_FIB_LKUP_RET_UNREACHABLE,  /* dest is unreachable; can be dropped */
  BPF_FIB_LKUP_RET_PROHIBIT,     /* dest not allowed; can be dropped */
  BPF_FIB_LKUP_RET_NOT_FWDED,    /* packet is not forwarded */
  BPF_FIB_LKUP_RET_FWD_DISABLED, /* fwding is not enabled on ingress */
  BPF_FIB_LKUP_RET_UNSUPP_LWT,   /* fwd requires encapsulation */
  BPF_FIB_LKUP_RET_NO_NEIGH,     /* no neighbor entry for nh */
  BPF_FIB_LKUP_RET_FRAG_NEEDED,  /* fragmentation required to fwd */
};

struct bpf_fib_lookup {
  /* input:  network family for lookup (AF_INET, AF_INET6)
  * output: network family of egress nexthop
  */
  u8	family;

  /* set if lookup is to consider L4 data - e.g., FIB rules */
  u8	l4_protocol;
  u16	sport;
  u16	dport;

  /* total length of packet from network header - used for MTU check */
  u16	tot_len;

  /* input: L3 device index for lookup
  * output: device index from FIB lookup
  */
  u32	ifindex;

  union {
    /* inputs to lookup */
    u8	tos;		/* AF_INET  */
    u32	flowinfo;	/* AF_INET6, flow_label + priority */

    /* output: metric of fib result (IPv4/IPv6 only) */
    u32	rt_metric;
};

  union {
    u32		ipv4_src;
    u32		ipv6_src[4];  /* in6_addr; network order */
};

  /* input to bpf_fib_lookup, ipv{4,6}_dst is destination address in
  * network header. output: bpf_fib_lookup sets to gateway address
  * if FIB lookup returns gateway route
  */
  union {
    u32		ipv4_dst;
    u32		ipv6_dst[4];  /* in6_addr; network order */
};

  /* output */
  u16	h_vlan_proto;
  u16	h_vlan_TCI;
  u8	smac[6];     /* ETH_ALEN */
  u8	dmac[6];     /* ETH_ALEN */
};

#define __kconfig __attribute__((section(".kconfig")))
#define __ksym __attribute__((section(".ksyms")))

#endif
