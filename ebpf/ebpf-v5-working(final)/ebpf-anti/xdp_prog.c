#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
} firewall_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} packet_log_events SEC(".maps");

SEC("xdp")
int xdp_firewall_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Check if ethernet header fits
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    struct rule_key key = {};
    key.src_ip = iph->saddr;
    key.dst_ip = iph->daddr;
    key.proto = iph->protocol;

    // Parse Transport Layer
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
        key.src_port = tcph->source;
        key.dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        key.src_port = udph->source;
        key.dst_port = udph->dest;
    }
    // For ICMP or others, ports remain 0

    struct rule_value *rule = bpf_map_lookup_elem(&firewall_rules, &key);
    if (rule) {
        // Rule found! Increment hit counter
        __sync_fetch_and_add(&rule->counter, 1);
        
        if (rule->action == ACTION_DROP)
            return XDP_DROP;  // Drop the packet immediately
        else
            return XDP_PASS;  // Pass the packet, don't log it
    }
    
    // No matching rule found - log packet for analysis
    struct packet_log log_entry = {};
    log_entry.src_ip = key.src_ip;
    log_entry.dst_ip = key.dst_ip;
    log_entry.src_port = key.src_port;
    log_entry.dst_port = key.dst_port;
    log_entry.proto = key.proto;
    log_entry.len = data_end - data;
    log_entry.timestamp = bpf_ktime_get_ns();
    
    if (key.proto == IPPROTO_TCP) {
         struct tcphdr *tcph = (void *)(iph + 1);
         if ((void *)(tcph + 1) <= data_end) {
             __u8 *tcp_flags_byte = (void *)tcph + 13;
             if ((void *)(tcp_flags_byte + 1) <= data_end) {
                 log_entry.tcp_flags = *tcp_flags_byte & 0x3F;
             }
         }
    }
    
    bpf_perf_event_output(ctx, &packet_log_events, BPF_F_CURRENT_CPU, &log_entry, sizeof(log_entry));
    
    return XDP_PASS;  // Let unmatched packets through
}

char _license[] SEC("license") = "GPL";
