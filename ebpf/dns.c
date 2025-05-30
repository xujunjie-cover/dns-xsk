#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include "common.h"


#define MAX_SOCKS 64

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} qidconf_map SEC(".maps");


SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{

	int *qidconf, index = ctx->rx_queue_index;
	// A set entry here means that the correspnding queue_id
	// has an active AF_XDP socket bound to it.
	qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
	if (!qidconf)
		return XDP_PASS;

	// redirect packets to an xdp socket that match the given IPv4 or IPv6 protocol; pass all other packets to the kernel
	void *data = (void*)(long)ctx->data;
	void *data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u16 h_proto = eth->h_proto;
	if ((void*)eth + sizeof(*eth) <= data_end) {
		if (bpf_htons(h_proto) == ETH_P_IP) {
			struct iphdr *ip = data + sizeof(*eth);
			if ((void*)ip + sizeof(*ip) <= data_end) {
				if (ip->protocol == IPPROTO_UDP) {
                    struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
                    if ((void*)udp + sizeof(*udp) <= data_end) {
                        if (udp->dest == bpf_htons(53)) {
                            if (*qidconf)
						        return bpf_redirect_map(&xsks_map, index, 0);
                        }
                    }
				}
			}
		} else if (bpf_htons(h_proto) == ETH_P_IPV6) {
			struct ipv6hdr *ip = data + sizeof(*eth);
			if ((void*)ip + sizeof(*ip) <= data_end) {
				if (ip->nexthdr == IPPROTO_UDP) {
                    struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
                    if ((void*)udp + sizeof(*udp) <= data_end) {
                        if (udp->dest == bpf_htons(53)) {
                            if (*qidconf)
						        return bpf_redirect_map(&xsks_map, index, 0);
                        }
                    }
				}
			}
		}
	}

	return XDP_PASS;
}

//Basic license just for compiling the object code
char _license[] SEC("license") = "GPL";
//char __license[] SEC("license") = "LGPL-2.1 or BSD-2-Clause";
