// SPDX-License-Identifier: GPL-2.0
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <bcc/helpers.h>

/* Fallback endian helpers if not provided */
#ifndef bpf_ntohs
#define bpf_ntohs(x) (__builtin_bswap16((__u16)(x)))
#endif
#ifndef bpf_htons
#define bpf_htons(x) (__builtin_bswap16((__u16)(x)))
#endif
#ifndef bpf_ntohl
#define bpf_ntohl(x) (__builtin_bswap32((__u32)(x)))
#endif
#ifndef bpf_htonl
#define bpf_htonl(x) (__builtin_bswap32((__u32)(x)))
#endif

#define ACTION_PASS 0
#define ACTION_DROP 1

#define MAX_RULES 64
#define REPORT_INTERVAL_PACKETS 8
#define REPORT_INTERVAL_NS (5ULL * 1000000000ULL) /* 5 seconds */

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 pad[3];
};

struct flow_metrics {
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 packets;
    __u64 bytes;
    __u32 tcp_flags;
    __u32 last_report_packets;
    __u64 last_report_ns;
};

struct rule {
    __u32 id;
    __u32 priority; /* lower value = higher priority */
    __u32 src_ip;
    __u32 src_ip_mask;
    __u32 dst_ip;
    __u32 dst_ip_mask;
    __u16 src_port;
    __u16 src_port_mask;
    __u16 dst_port;
    __u16 dst_port_mask;
    __u8 proto;
    __u8 proto_mask;
    __u8 action;
    __u8 active;
    __u64 min_packets;
    __u64 max_packets;
    __u64 min_bytes;
    __u64 max_bytes;
    __u64 min_bps;
    __u64 max_bps;
    __u64 min_pps;
    __u64 max_pps;
    __u32 required_flags;
    __u32 forbidden_flags;
};

struct ml_decision {
    __u8 action; /* ACTION_PASS or ACTION_DROP */
    __u8 confidence; /* reserved for future use */
    __u16 reserved;
    __u64 expires_ns; /* 0 for no expiry */
};

struct feature_event {
    struct flow_key key;
    __u64 duration_ns;
    __u64 packets;
    __u64 bytes;
    __u64 bps;
    __u64 pps;
    __u32 tcp_flags;
    __u32 log2_bytes;
    __u32 log2_packets;
    __u16 src_port;
    __u16 dst_port;
    __u8 tcp;
    __u8 udp;
    __u8 icmp;
    __u8 src_port_low;
    __u8 src_port_high;
    __u8 dst_port_low;
    __u8 dst_port_high;
};

BPF_LRU_HASH(flow_state_map, struct flow_key, struct flow_metrics, 65536);
BPF_ARRAY(rules_map, struct rule, MAX_RULES);
BPF_HASH(ml_decision_map, struct flow_key, struct ml_decision, 16384);
BPF_PERF_OUTPUT(feature_events);

static __always_inline __u32 log2_u64(__u64 value) {
    if (!value)
        return 0;
    return 63 - __builtin_clzll(value);
}

static __always_inline __u32 build_tcp_flag_mask(const struct tcphdr *tcph) {
    __u32 mask = 0;
    if (tcph->fin)
        mask |= TCP_FLAG_FIN;
    if (tcph->syn)
        mask |= TCP_FLAG_SYN;
    if (tcph->rst)
        mask |= TCP_FLAG_RST;
    if (tcph->psh)
        mask |= TCP_FLAG_PSH;
    if (tcph->ack)
        mask |= TCP_FLAG_ACK;
    if (tcph->urg)
        mask |= TCP_FLAG_URG;
    return mask;
}

static __always_inline int rule_matches(const struct rule *r,
                                        const struct flow_key *key,
                                        const struct flow_metrics *metrics,
                                        __u64 bps,
                                        __u64 pps) {
    if (!r->active)
        return 0;

    if (r->src_ip_mask &&
        (r->src_ip & r->src_ip_mask) != (key->src_ip & r->src_ip_mask))
        return 0;

    if (r->dst_ip_mask &&
        (r->dst_ip & r->dst_ip_mask) != (key->dst_ip & r->dst_ip_mask))
        return 0;

    if (r->src_port_mask &&
        (r->src_port & r->src_port_mask) != (key->src_port & r->src_port_mask))
        return 0;

    if (r->dst_port_mask &&
        (r->dst_port & r->dst_port_mask) != (key->dst_port & r->dst_port_mask))
        return 0;

    if (r->proto_mask &&
        (r->proto & r->proto_mask) != (key->proto & r->proto_mask))
        return 0;

    if (r->min_packets && metrics->packets < r->min_packets)
        return 0;
    if (r->max_packets && metrics->packets > r->max_packets)
        return 0;

    if (r->min_bytes && metrics->bytes < r->min_bytes)
        return 0;
    if (r->max_bytes && metrics->bytes > r->max_bytes)
        return 0;

    if (r->min_bps && bps < r->min_bps)
        return 0;
    if (r->max_bps && bps > r->max_bps)
        return 0;

    if (r->min_pps && pps < r->min_pps)
        return 0;
    if (r->max_pps && pps > r->max_pps)
        return 0;

    if (r->required_flags &&
        (metrics->tcp_flags & r->required_flags) != r->required_flags)
        return 0;

    if (r->forbidden_flags &&
        (metrics->tcp_flags & r->forbidden_flags))
        return 0;

    return 1;
}

static __always_inline void emit_feature_event(struct xdp_md *ctx,
                                              const struct flow_key *key,
                                              struct flow_metrics *metrics,
                                              __u64 bps,
                                              __u64 pps) {
    struct feature_event event = {};
    event.key = *key;
    event.duration_ns = metrics->last_seen_ns - metrics->first_seen_ns;
    event.packets = metrics->packets;
    event.bytes = metrics->bytes;
    event.bps = bps;
    event.pps = pps;
    event.tcp_flags = metrics->tcp_flags;
    event.log2_bytes = log2_u64(metrics->bytes + 1);
    event.log2_packets = log2_u64(metrics->packets + 1);
    event.src_port = key->src_port;
    event.dst_port = key->dst_port;
    event.tcp = key->proto == IPPROTO_TCP;
    event.udp = key->proto == IPPROTO_UDP;
    event.icmp = key->proto == IPPROTO_ICMP;
    event.src_port_low = key->src_port && key->src_port < 1024;
    event.src_port_high = key->src_port > 49151;
    event.dst_port_low = key->dst_port && key->dst_port < 1024;
    event.dst_port_high = key->dst_port > 49151;

    feature_events.perf_submit(ctx, &event, sizeof(event));
}

int xdp_feature_guard(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u64 packet_len = (__u64)(data_end - data);

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.proto = ip->protocol;

    void *trans = (void *)ip + (ip->ihl * 4);
    if (trans > data_end)
        return XDP_PASS;

    __u32 tcp_flags = 0;

    if (key.proto == IPPROTO_TCP) {
        struct tcphdr *tcph = trans;
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
        key.src_port = bpf_ntohs(tcph->source);
        key.dst_port = bpf_ntohs(tcph->dest);
        tcp_flags = build_tcp_flag_mask(tcph);
    } else if (key.proto == IPPROTO_UDP) {
        struct udphdr *udph = trans;
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        key.src_port = bpf_ntohs(udph->source);
        key.dst_port = bpf_ntohs(udph->dest);
    } else {
        key.src_port = 0;
        key.dst_port = 0;
    }

    __u64 now = bpf_ktime_get_ns();
    struct flow_metrics *metrics = flow_state_map.lookup(&key);

    if (!metrics) {
        struct flow_metrics zero = {};
        zero.first_seen_ns = now;
        zero.last_seen_ns = now;
        zero.packets = 0;
        zero.bytes = 0;
        zero.tcp_flags = 0;
        zero.last_report_packets = 0;
        zero.last_report_ns = 0;
        flow_state_map.update(&key, &zero);
        metrics = flow_state_map.lookup(&key);
        if (!metrics)
            return XDP_PASS;
    }

    metrics->last_seen_ns = now;
    metrics->packets += 1;
    metrics->bytes += packet_len;
    if (tcp_flags)
        metrics->tcp_flags |= tcp_flags;

    __u64 duration_ns = metrics->last_seen_ns - metrics->first_seen_ns;
    if (duration_ns == 0)
        duration_ns = 1;

    __u64 duration_us = duration_ns / 1000;
    if (duration_us == 0)
        duration_us = 1;

    __u64 bps = (metrics->bytes * 8000000ULL) / duration_us;
    __u64 pps = (metrics->packets * 1000000ULL) / duration_us;

    int verdict = -1;
    __u32 best_priority = 0xFFFFFFFF;

#pragma clang loop unroll(full)
    for (__u32 i = 0; i < MAX_RULES; i++) {
        struct rule *r = rules_map.lookup(&i);
        if (!r)
            continue;
        if (r->priority > best_priority)
            continue;
        if (!rule_matches(r, &key, metrics, bps, pps))
            continue;
        best_priority = r->priority;
        verdict = r->action;
    }

    if (verdict == ACTION_DROP)
        return XDP_DROP;
    if (verdict == ACTION_PASS)
        return XDP_PASS;

    struct ml_decision *decision = ml_decision_map.lookup(&key);
    if (decision) {
        if (!decision->expires_ns || decision->expires_ns > now) {
            if (decision->action == ACTION_DROP)
                return XDP_DROP;
            return XDP_PASS;
        }
        ml_decision_map.delete(&key);
    }

    if (!metrics->last_report_packets ||
        metrics->packets - metrics->last_report_packets >= REPORT_INTERVAL_PACKETS ||
        now - metrics->last_report_ns >= REPORT_INTERVAL_NS) {
        emit_feature_event(ctx, &key, metrics, bps, pps);
        metrics->last_report_packets = metrics->packets;
        metrics->last_report_ns = now;
    }

    return XDP_PASS;
}

char _license[] = "GPL";