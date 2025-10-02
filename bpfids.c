#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>


#define OR(a, b) ((a) | (b))
#define AND(a, b) ((a) & (b))
#define NOT(a) (~(a))
#define XOR(a, b) ((a) ^ (b))
#define EQ(a, b) ((a) == (b))
#define NEQ(a, b) ((a) != (b))

struct filter_context
{
    __u32 src_ip;
    __u32 dst_ip;
    struct in6_addr src_ip6;
    struct in6_addr dst_ip6;
};


const static inline struct in6_addr apply_ipv6_netmask(const struct in6_addr *ip, __u8 prefix)
{
    struct in6_addr masked_ip = {};
    if (prefix > 128)
        prefix = 128;
    int full_segments = prefix / 16;
    int remaining_bits = prefix % 16;
    for (int i = 0; i < full_segments; i++)
    {
        masked_ip.in6_u.u6_addr16[i] = ip->in6_u.u6_addr16[i];
    }
    if (remaining_bits > 0 && full_segments < 8)
    {
        __u16 mask = (__u16)(~0) << (16 - remaining_bits);
        masked_ip.in6_u.u6_addr16[full_segments] = ip->in6_u.u6_addr16[full_segments] & mask;
    }
    return masked_ip;
}

SEC("xdp")
int packet_filter(struct xdp_md *ctx)
{
    bpf_printk("Packet filter triggered\n");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct filter_context fctx = {0};
    __u8 is_ipv4 = 0;
    __u8 is_ipv6 = 0;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        fctx.src_ip = bpf_ntohl(ip->saddr);
        fctx.dst_ip = bpf_ntohl(ip->daddr);
    is_ipv4 = 1;
    } else if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        fctx.src_ip6 = ip6->saddr;
        fctx.dst_ip6 = ip6->daddr;
    is_ipv6 = 1;
    }

    /* Generated rules: first match returns */
#if __has_include("bpfidsrules.c")
#include "bpfidsrules.c"
#else
    /* Use bpf_printk (libbpf helper macro) instead of raw bpf_trace_printk with size 0 */
    bpf_printk("No rules file found\n");
#endif
    (void)is_ipv4;
    (void)is_ipv6;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
