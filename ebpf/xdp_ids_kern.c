// BCC-compatible XDP program to extract packet features for IDS
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>

struct feature_event {
    __u64 ts_ns;
    __u8 ip_version;     // 4 or 6
    __u8 protocol;       // IP protocol
    __u16 tcp_flags;     // for TCP
    __u16 sport;
    __u16 dport;
    __u32 pkt_len;
    __u32 payload_len;
    __u32 tos;           // IPv4 TOS or IPv6 traffic class
};

BPF_PERF_OUTPUT(events);

static __always_inline int parse_ipv4(void *data, void *data_end, struct feature_event *ev) {
    struct iphdr *ip4h = data;
    if ((void *)(ip4h + 1) > data_end) return -1;
    ev->ip_version = 4;
    ev->protocol = ip4h->protocol;
    ev->tos = ip4h->tos;
    __u16 ihl_bytes = ip4h->ihl * 4;
    __u32 tot_len = bpf_ntohs(ip4h->tot_len);
    ev->payload_len = tot_len > ihl_bytes ? tot_len - ihl_bytes : 0;

    void *l4 = (void *)ip4h + ihl_bytes;
    if (l4 > data_end) return 0;

    if (ip4h->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end) return 0;
        ev->sport = bpf_ntohs(tcph->source);
        ev->dport = bpf_ntohs(tcph->dest);
        ev->tcp_flags = ((__u16)tcph->fin) | (((__u16)tcph->syn) << 1) | (((__u16)tcph->rst) << 2) |
                        (((__u16)tcph->psh) << 3) | (((__u16)tcph->ack) << 4) | (((__u16)tcph->urg) << 5) |
                        (((__u16)tcph->ece) << 6) | (((__u16)tcph->cwr) << 7);
    } else if (ip4h->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end) return 0;
        ev->sport = bpf_ntohs(udph->source);
        ev->dport = bpf_ntohs(udph->dest);
    }
    return 0;
}

static __always_inline int parse_ipv6(void *data, void *data_end, struct feature_event *ev) {
    struct ipv6hdr *ip6h = data;
    if ((void *)(ip6h + 1) > data_end) return -1;
    ev->ip_version = 6;
    ev->protocol = ip6h->nexthdr;
    // Traffic class = (priority << 4) | (flow_lbl[0] >> 4)
    ev->tos = (((__u32)ip6h->priority) << 4) | (((__u32)ip6h->flow_lbl[0]) >> 4);

    void *l4 = (void *)ip6h + sizeof(*ip6h);
    if (l4 > data_end) return 0;

    if (ip6h->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end) return 0;
        ev->sport = bpf_ntohs(tcph->source);
        ev->dport = bpf_ntohs(tcph->dest);
        ev->tcp_flags = ((__u16)tcph->fin) | (((__u16)tcph->syn) << 1) | (((__u16)tcph->rst) << 2) |
                        (((__u16)tcph->psh) << 3) | (((__u16)tcph->ack) << 4) | (((__u16)tcph->urg) << 5) |
                        (((__u16)tcph->ece) << 6) | (((__u16)tcph->cwr) << 7);
    } else if (ip6h->nexthdr == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end) return 0;
        ev->sport = bpf_ntohs(udph->source);
        ev->dport = bpf_ntohs(udph->dest);
    }

    // IPv6 payload length is header field (excludes IPv6 header)
    ev->payload_len = bpf_ntohs(ip6h->payload_len);
    return 0;
}

int xdp_ids(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct feature_event ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pkt_len = (__u32)((long)data_end - (long)data);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *nh = (void *)(eth + 1);

    if (bpf_ntohs(h_proto) == ETH_P_IP) {
        if (parse_ipv4(nh, data_end, &ev) < 0) return XDP_PASS;
    } else if (bpf_ntohs(h_proto) == ETH_P_IPV6) {
        if (parse_ipv6(nh, data_end, &ev) < 0) return XDP_PASS;
    } else {
        return XDP_PASS;
    }

    events.perf_submit(ctx, &ev, sizeof(ev));
    return XDP_PASS;
}
