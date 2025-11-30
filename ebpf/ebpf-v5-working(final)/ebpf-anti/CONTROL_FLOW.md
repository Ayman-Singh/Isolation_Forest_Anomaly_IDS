# eBPF Firewall Control Flow

This document explains how packets are evaluated and how the BPF map works in the firewall.

## Control Flow Overview

### 1. **Packet Arrival at XDP Hook**

When a packet arrives at the network interface (e.g., `lo` or `enp0s3`), the XDP program `xdp_firewall_func()` in `xdp_prog.c` is triggered **before** the kernel's networking stack processes it.

```c
SEC("xdp")
int xdp_firewall_func(struct xdp_md *ctx) {
```

### 2. **Packet Parsing**

The program extracts packet headers to understand what kind of packet it is:

```c
// Get packet boundaries
void *data_end = (void *)(long)ctx->data_end;
void *data = (void *)(long)ctx->data;

// Parse Ethernet header
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;  // Incomplete packet, let it pass

// Check if it's IPv4
if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;  // Not IPv4, let it pass

// Parse IP header
struct iphdr *iph = (void *)(eth + 1);
if ((void *)(iph + 1) > data_end)
    return XDP_PASS;
```

### 3. **Building the Rule Key**

The program creates a lookup key from the packet's 5-tuple:

```c
struct rule_key key = {};
key.src_ip = iph->saddr;      // Source IP
key.dst_ip = iph->daddr;      // Destination IP
key.proto = iph->protocol;    // Protocol (TCP=6, UDP=17, ICMP=1)

// For TCP packets, extract ports
if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)(iph + 1);
    key.src_port = tcph->source;
    key.dst_port = tcph->dest;
}
// For UDP packets, extract ports
else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (void *)(iph + 1);
    key.src_port = udph->source;
    key.dst_port = udph->dest;
}
// For ICMP, ports remain 0
```

### 4. **BPF Map Lookup**

The program searches the `firewall_rules` hash map using the key:

```c
struct rule_value *rule = bpf_map_lookup_elem(&firewall_rules, &key);
```

**How the BPF Map Works:**

The `firewall_rules` map is defined as:
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);     // Hash table for fast lookup
    __uint(max_entries, 1024);           // Max 1024 rules
    __type(key, struct rule_key);        // Key: 5-tuple
    __type(value, struct rule_value);    // Value: action + counter
} firewall_rules SEC(".maps");
```

- **Type**: `BPF_MAP_TYPE_HASH` - a hash table that maps keys to values
- **Key**: The 5-tuple (src_ip, dst_ip, src_port, dst_port, proto)
- **Value**: Contains `action` (DROP/PASS) and a `counter` for statistics
- **Lookup**: O(1) average time complexity - very fast!

### 5. **Packet Decision**

Based on the lookup result:

```c
if (rule) {
    // Rule found! Increment hit counter
    __sync_fetch_and_add(&rule->counter, 1);
    
    if (rule->action == ACTION_DROP)
        return XDP_DROP;    // Drop the packet immediately
    else
        return XDP_PASS;    // Pass the packet, don't log it
}
```

**Return Values:**
- `XDP_DROP`: Packet is silently dropped at the driver level (fastest drop)
- `XDP_PASS`: Packet continues to kernel networking stack

**Important:** If a rule matches with `ACTION_PASS`, the packet is passed immediately WITHOUT logging. Only packets with NO matching rule are logged.

### 6. **Logging Unmatched Packets**

If no rule matches, log the packet to userspace:

```c
else {
    // No rule found - log for analysis
    struct packet_log log_entry = {};
    log_entry.src_ip = key.src_ip;
    log_entry.dst_ip = key.dst_ip;
    log_entry.src_port = key.src_port;
    log_entry.dst_port = key.dst_port;
    log_entry.proto = key.proto;
    
    // Extract TCP flags if it's a TCP packet
    if (key.proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) <= data_end) {
            __u8 *tcp_flags_byte = (void *)tcph + 13;
            if ((void *)(tcp_flags_byte + 1) <= data_end) {
                log_entry.tcp_flags = *tcp_flags_byte & 0x3F;
            }
        }
    }
    
    // Send to userspace via perf buffer
    bpf_perf_event_output(ctx, &packet_log_events, BPF_F_CURRENT_CPU, 
                          &log_entry, sizeof(log_entry));
}

return XDP_PASS;  // Let unmatched packets through
```

## Userspace Interaction

### Adding a Rule (`manager.c`)

When you run `sudo ./manager add --src 127.0.0.1 --dport 8080 --proto tcp --action drop`:

```c
int do_add(int argc, char **argv) {
    struct rule_key key;
    struct rule_value val;
    
    // Parse CLI arguments into key and value
    parse_rule_args(argc, argv, &key, &val);
    
    // Get the pinned map file descriptor
    map_fd = bpf_obj_get(PIN_PATH);
    
    // Insert into the hash map
    bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
}
```

**The map is pinned** to `/sys/fs/bpf/xdp_firewall_map` so it persists even after the manager program exits.

### Monitoring Logs (`manager.c`)

When you run `sudo ./manager monitor`:

```c
int do_monitor() {
    // Get perf buffer map
    map_fd = bpf_obj_get(PIN_PATH_PERF);
    
    // Open JSON file in append mode
    fp = fopen("firewall_log.json", "a");
    
    // Create perf buffer to receive events from kernel
    pb = perf_buffer__new(map_fd, 8, handle_event, NULL, fp, NULL);
    
    // Poll for events (blocking)
    while (1) {
        perf_buffer__poll(pb, 100);
    }
}

// Called when kernel sends a log event
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct packet_log *e = data;
    FILE *fp = ctx;
    
    // Write JSON to file
    fprintf(fp, "{\"src_ip\": \"%d.%d.%d.%d\", ...}\n", ...);
    fflush(fp);
}
```

## Visual Flow Diagram

```
Packet arrives → XDP Hook (xdp_firewall_func)
                      ↓
                 Parse headers
                      ↓
              Extract 5-tuple → Build rule_key
                      ↓
           Lookup in firewall_rules map
                      ↓
                 Rule found?
                /           \
              YES            NO
               ↓              ↓
        Increment counter   Log to perf buffer
               ↓              ↓
        Check action     Return XDP_PASS
          /      \
      DROP      PASS
        ↓        ↓
   XDP_DROP  XDP_PASS
   (dropped) (continues)
```

## Key Performance Benefits

1. **Early packet drop**: XDP runs before kernel allocates socket buffers → minimal CPU usage
2. **O(1) hash lookup**: Finding rules is extremely fast
3. **No context switching**: Everything runs in kernel space until logging
4. **Lock-free counters**: `__sync_fetch_and_add` for thread-safe statistics

This architecture allows the firewall to process millions of packets per second with minimal overhead!

## Data Structures

### rule_key (common.h)
```c
struct rule_key {
    __u32 src_ip;      // Source IP address
    __u32 dst_ip;      // Destination IP address
    __u16 src_port;    // Source port
    __u16 dst_port;    // Destination port
    __u8  proto;       // Protocol (6=TCP, 17=UDP, 1=ICMP)
    __u8  pad[3];      // Padding for alignment
};
```

### rule_value (common.h)
```c
struct rule_value {
    __u32 action;      // ACTION_DROP (1) or ACTION_PASS (0)
    __u64 counter;     // Number of packets matched
};
```

### packet_log (common.h)
```c
struct packet_log {
    __u32 src_ip;      // Source IP address
    __u32 dst_ip;      // Destination IP address
    __u16 src_port;    // Source port
    __u16 dst_port;    // Destination port
    __u8  proto;       // Protocol number
    __u8  tcp_flags;   // TCP flags (if TCP packet)
    __u8  pad[2];      // Padding
};
```

## Map Pinning

The firewall uses **map pinning** to persist the BPF maps in the filesystem:

- Rule map: `/sys/fs/bpf/xdp_firewall_map`
- Perf event map: `/sys/fs/bpf/xdp_packet_log`

This allows the `manager` program to:
1. Load the XDP program once
2. Exit and let the program keep running
3. Re-open the map later to add/delete rules
4. Access the same map from multiple processes

## Summary

The firewall uses a **hash map** for O(1) rule lookups and **perf buffers** for efficient kernel-to-userspace communication. The XDP hook processes packets at the earliest possible point, providing maximum performance and minimal latency.
