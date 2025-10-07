#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>
#include <linux/time.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Header existence helpers
/*
 * Timer based rolling counters
 * We maintain a monotonic total per rule plus snapshot values captured
 * at 1s, 60s, 3600s, 86400s intervals. Userspace can compute the count
 * over the last window W as (total - snapshot_W). A periodic per-rule
 * bpf_timer updates the snapshots. This avoids maintaining large ring
 * buffers inside eBPF while still giving rolling window semantics.
 */

struct rule_counters {
    struct bpf_timer timer;      /* MUST be first field */
    __u64 total;                 /* Monotonic total hits */
    __u64 snap_1s;               /* Total value captured >=1s ago */
    __u64 snap_60s;              /* Captured >=60s ago */
    __u64 snap_3600s;            /* Captured >=3600s ago */
    __u64 snap_86400s;           /* Captured >=86400s ago */
    __u64 ts_1s;                 /* Last time snap_1s updated */
    __u64 ts_60s;                /* Last time snap_60s updated */
    __u64 ts_3600s;              /* Last time snap_3600s updated */
    __u64 ts_86400s;             /* Last time snap_86400s updated */
    __u64  initialized;           /* One-time timer init guard */
};

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, struct rule_counters);
        __uint(max_entries, 1024);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_counters_map SEC(".maps");

/* Forward declaration of timer callback so we can reference it in rule_hit */
static int rule_timer_cb(void *map, int *key, struct rule_counters *rc);

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, long);
        __uint(max_entries, 1024);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_hits SEC(".maps");


struct filter_context
{
    struct ethhdr *eth;
    struct iphdr *ip;
    struct ipv6hdr *ip6;
    struct tcphdr *tcp;
    struct udphdr *udp;
    __u32 src_ip;
    __u32 dst_ip;
    struct in6_addr src_ip6;
    struct in6_addr dst_ip6;
    __u16 udp_src_port;
    __u16 udp_dst_port;
    __u16 tcp_src_port;
    __u16 tcp_dst_port;
};

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};
struct ipv6_lpm_key {
        __u32 prefixlen;
        struct in6_addr data;
};

const static inline struct in6_addr  apply_ipv6_netmask(const struct in6_addr *ip, __u8 prefix) 
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
static inline void rule_hit(__u32 rule_id)
{
    __u32 key = rule_id;
    long *value = bpf_map_lookup_elem(&rule_hits, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    } else {
        long initial_value = 1;
        bpf_map_update_elem(&rule_hits, &key, &initial_value, BPF_ANY);
    }

    /* Timed counters */
    struct rule_counters *rc = bpf_map_lookup_elem(&rule_counters_map, &key);
    if (!rc) {
        return; /* Should not happen for ARRAY map, but be safe */
    }
    /* Initialize timer once */
    if (!rc->initialized) {
        /* Attempt to obtain a lock-free one-time init using xchg on initialized */
        __u8 zero = 0;
        if (__sync_bool_compare_and_swap(&rc->initialized, zero, 1)) {
            __u64 now = bpf_ktime_get_ns();
            rc->ts_1s = rc->ts_60s = rc->ts_3600s = rc->ts_86400s = now;
            rc->snap_1s = rc->snap_60s = rc->snap_3600s = rc->snap_86400s = 0;
            /* Prepare timer */
            bpf_timer_init(&rc->timer, &rule_counters_map, CLOCK_MONOTONIC);
            bpf_timer_set_callback(&rc->timer, rule_timer_cb);
            /* Fire first callback after 1 second */
            bpf_timer_start(&rc->timer, 1000000000ULL /*1s*/, 0);
        }
    }
    __sync_fetch_and_add(&rc->total, 1);
}

/* Timer callback updates snapshots for each rule. */
static int rule_timer_cb(void *map, int *key, struct rule_counters *rc)
{
    __u64 now = bpf_ktime_get_ns();
    const __u64 NS_1S = 1000000000ULL;
    const __u64 NS_60S = 60ULL * 1000000000ULL;
    const __u64 NS_3600S = 3600ULL * 1000000000ULL;
    const __u64 NS_86400S = 86400ULL * 1000000000ULL;

    /* Update snapshots if interval elapsed. We use >= to tolerate drift */
    if (now - rc->ts_1s >= NS_1S) {
        rc->snap_1s = rc->total;
        rc->ts_1s = now;
    }
    if (now - rc->ts_60s >= NS_60S) {
        rc->snap_60s = rc->total;
        rc->ts_60s = now;
    }
    if (now - rc->ts_3600s >= NS_3600S) {
        rc->snap_3600s = rc->total;
        rc->ts_3600s = now;
    }
    if (now - rc->ts_86400s >= NS_86400S) {
        rc->snap_86400s = rc->total;
        rc->ts_86400s = now;
    }

    /* Reschedule for next second */
    bpf_timer_start(&rc->timer, NS_1S, 0);
    return 0;
}


// Header existence helpers
static __always_inline __u32 extract_src_ipv4(const struct iphdr *ip) {
    return bpf_ntohl(ip->saddr);
}

static __always_inline __u32 extract_dst_ipv4(const struct iphdr *ip) {
    return bpf_ntohl(ip->daddr);
}

static __always_inline struct in6_addr extract_src_ipv6(const struct ipv6hdr *ip6) {
    return ip6->saddr;
}

static __always_inline struct in6_addr extract_dst_ipv6(const struct ipv6hdr *ip6) {
    return ip6->daddr;
}

static __always_inline __u16 extract_tcp_src_port(const struct tcphdr *th) {
    return bpf_ntohs(th->source);
}

static __always_inline __u16 extract_tcp_dst_port(const struct tcphdr *th) {
    return bpf_ntohs(th->dest);
}

static __always_inline __u16 extract_udp_src_port(const struct udphdr *uh) {
    return bpf_ntohs(uh->source);
}

static __always_inline __u16 extract_udp_dst_port(const struct udphdr *uh) {
    return bpf_ntohs(uh->dest);
}

static __always_inline struct ethhdr *parse_ethhdr(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return NULL;
    return eth;
}

static __always_inline struct iphdr *parse_iphdr(struct ethhdr *eth, void *data_end) {
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return NULL;
        return ip;
    }
    return NULL;
}

static __always_inline struct ipv6hdr *parse_ipv6hdr(struct ethhdr *eth, void *data_end) {
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return NULL;
        return ip6;
    }
    return NULL;
}

static __always_inline struct tcphdr *parse_tcphdr(struct ethhdr* eth, void *data_end) {
    struct iphdr *ip = parse_iphdr(eth, data_end);
    if (ip && ip->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)ip + (ip->ihl * 4);
        if ((void *)(th + 1) > data_end)
            return NULL;
        return th;
    }
    struct ipv6hdr *ip6 = parse_ipv6hdr(eth, data_end);
    if (ip6 && ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *th = (void *)(ip6 + 1);
        if ((void *)(th + 1) > data_end)
            return NULL;
        return th;
    }
    return NULL;
}

static __always_inline struct udphdr *parse_udphdr(struct ethhdr* eth, void *data_end) {
    struct iphdr *ip = parse_iphdr(eth, data_end);
    if (ip && ip->protocol == IPPROTO_UDP) {
        struct udphdr *uh = (void *)ip + (ip->ihl * 4);
        if ((void *)(uh + 1) > data_end)
            return NULL;
        return uh;
    }
    struct ipv6hdr *ip6 = parse_ipv6hdr(eth, data_end);
    if (ip6 && ip6->nexthdr == IPPROTO_UDP) {
        struct udphdr *uh = (void *)(ip6 + 1);
        if ((void *)(uh + 1) > data_end)
            return NULL;
        return uh;
    }
    return NULL;
}
#if __has_include("bpfidsrules.c")
#include "bpfidsrules.c"
#else
    /* Use bpf_printk (libbpf helper macro) instead of raw bpf_trace_printk with size 0 */
const static int evaluate_rules(struct filter_context fctx, void *data, void* data_end) {
    bpf_printk("No rules file found\n");
    return XDP_PASS;
}
#endif

SEC("xdp")
int packet_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct filter_context fctx = {0};
    /* Feature extraction is now deferred. bpfidsrules.c should call extraction helpers as needed. */
    return evaluate_rules(fctx, data, data_end);
}

char _license[] SEC("license") = "GPL";
