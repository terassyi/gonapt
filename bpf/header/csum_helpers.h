
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "bpf_helpers.h"

#define DEBUG 1

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

static inline __u16 csum_fold_helper(__u64 csum) {
	int i;
#pragma unroll
	for (i = 0; i < 4; i++) {
		if (csum >> 16) {
			csum = (csum & 0xffff) + (csum >> 16);
		}
	}
	return ~csum;
}

static inline void ipv4_csum(void *data_start, int data_size, __u64 *csum) {
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}

static inline void ipv4_csum_inline(void *iph, __u64 *csum) {
	__u16 *next_iph_u16 = (__u16 *)iph;
	for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
		*csum += *next_iph_u16++;
	}
	*csum = csum_fold_helper(*csum);
}

static inline void icmp_ident_csum_update(struct icmphdr *icmph, __u16 new_ident) {
	__u64 csum = (__u64)icmph->checksum;
	__u32 tmp = 0;
	bpf_printk("csum %x", csum);
	//tmp = __builtin_bswap32((__u32)icmph->un.echo.id);
	tmp = (__u32)icmph->un.echo.id;
	csum = bpf_csum_diff(&tmp, sizeof(__u32), 0, 0, csum);
	bpf_printk("csum %x", csum);
	// tmp = __builtin_bswap32((__u32)new_ident);
	tmp = (__u32)new_ident;
	csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), csum);
	bpf_printk("csum %x", csum);
	csum = csum_fold_helper(csum);
	icmph->checksum = csum;
}

static inline __u16 ipv4_csum_update_u16(__u16 csum, __u16 old_val, __u16 new_val) {
	__u32 a = ~ntohs(csum) & 0x0000ffff;
	__u32 b = ntohs(new_val) & 0x0000ffff;
	__u32 c = ~ntohs(old_val) & 0x0000ffff;
	__u32 sum = a + b + c;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return ~htons(sum);
}

static inline __u16 ipv4_csum_update_u32(__u16 csum, __u32 old_val, __u32 new_val) {
	__u16 old_val_head = old_val >> 16;
	__u16 new_val_head = new_val >> 16;
	__u16 old_val_tail = old_val;
	__u16 new_val_tail = new_val;
	csum = ipv4_csum_update_u16(csum, old_val_head, new_val_head);
	return ipv4_csum_update_u16(csum, old_val_tail, new_val_tail);
}

static inline void ipv4_l4_csum(void *data_start, int data_size, __u64 *csum, struct iphdr *iph) {
	__u32 tmp = 0;
	*csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__u32), *csum);
	*csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__u32), *csum);
	tmp = __builtin_bswap32((__u32)iph->protocol);
	*csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
	tmp = __builtin_bswap32((__u32)data_size);
	*csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}
