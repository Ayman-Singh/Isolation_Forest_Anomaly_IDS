// xdp_fw.c
// Minimal XDP firewall using an ARRAY of rules (bounded scan).
// Feature set (exact): src_ip (CIDR prefix), dst_port (0=any), protocol (0=any), pkt_len_threshold (0=ignore)
// Rule selection: matching rules -> choose smallest priority (numerically) -> action DROP or FORWARD
// Maps are left for userspace to pin after program load (bpftool used in userspace tool).
//
// NOTE: For production, consider offloading lookups (LPM, hashed indexes) and rate-limiting updates.
// This example favors simplicity and correctness for teaching / testing.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define MAX_RULES 128

enum action_t {
    ACTION_FORWARD = 0,
    ACTION_DROP = 1,
};

struct rule {
    __u32 id;
    __u32 priority;         // lower = higher priority
    __u32 src_ip;           // network byte order (big-endian)
    __u32 prefix_len;       // 0 = any
    __u32 dst_port;         // 0 = any (host order)
    __u32 proto;            // 0 = any
    __u32 pkt_len_threshold; // 0 = ignore, else drop if pkt_len <= threshold
    __u32 action;           // 0 = FORWARD, 1 = DROP
    __u32 active;           // 0 = empty, 1 = used
};

// rules array (indexed, bounded scan)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct rule);
} rules_map SEC(".maps");

// meta map for default action (single element, key=0)
struct meta {
    __u32 default_action; // 0=forward, 1=drop
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct meta);
} meta_map SEC(".maps");

static __always_inline __u32 ip_to_u32(const struct iphdr *ip) {
    return ip->saddr;
}

static __always_inline __u32 min_u32(__u32 a, __u32 b) { return a < b ? a : b; }

// compute mask for prefix_len (0..32)
static __always_inline __u32 prefix_mask_u32(__u32 prefix_len) {
    if (prefix_len == 0) return 0x00000000;
    return prefix_len == 32 ? 0xFFFFFFFF : (__u32)(0xFFFFFFFF << (32 - prefix_len));
}

SEC("xdp")
int xdp_fw_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u32 pkt_len = (__u32)(data_end - data);

    // basic bounds check for eth header
    if ((void*)(eth + 1) > data_end) return XDP_PASS;

    // Only handle IPv4 packets in this minimal example
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void*)(ip + 1) > data_end) return XDP_PASS;

    __u32 src_ip = ip->saddr; // already network byte order
    __u32 proto = ip->protocol;

    // default action
    __u32 zero = 0;
    struct meta *m = bpf_map_lookup_elem(&meta_map, &zero);
    __u32 final_action = ACTION_FORWARD;
    if (m) final_action = m->default_action;

    // Prepare transport info if available
    __u16 dst_port = 0; // host order
    // transport header start
    void *trans = (void*)ip + (ip->ihl * 4);
    if (trans <= data_end) {
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = trans;
            if ((void*)(tcph + 1) <= data_end) {
                dst_port = bpf_ntohs(tcph->dest);
            }
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udph = trans;
            if ((void*)(udph + 1) <= data_end) {
                dst_port = bpf_ntohs(udph->dest);
            }
        } else {
            dst_port = 0;
        }
    }

    // Scan rules array (bounded loop). Keep best match by priority (smallest numeric).
    __u32 best_priority = (__u32)0xFFFFFFFF;
    __u32 best_action = final_action;
    #pragma unroll
    for (__u32 i = 0; i < MAX_RULES; i++) {
        struct rule *r = bpf_map_lookup_elem(&rules_map, &i);
        if (!r) continue;
        if (r->active == 0) continue;

        // src_ip match (CIDR)
        if (r->prefix_len != 0) {
            __u32 mask = prefix_mask_u32(r->prefix_len);
            if ((r->src_ip & mask) != (src_ip & mask)) continue;
        }

        // proto match
        if (r->proto != 0 && r->proto != proto) continue;

        // pkt length threshold: rule says "drop if packet length <= N", store N in pkt_len_threshold
        if (r->pkt_len_threshold != 0) {
            if (!(pkt_len <= r->pkt_len_threshold)) {
                // if not <= threshold then rule does not apply
                continue;
            }
        }

        // dst port match (0=any)
        if (r->dst_port != 0) {
            if (dst_port == 0) continue; // no transport parsed
            if (r->dst_port != dst_port) continue;
        }

        // matched: check priority
        if (r->priority < best_priority) {
            best_priority = r->priority;
            best_action = r->action;
            if (best_priority == 0) break; // can't beat priority 0
        }
    }

    if (best_action == ACTION_DROP) {
        return XDP_DROP;
    } else {
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
