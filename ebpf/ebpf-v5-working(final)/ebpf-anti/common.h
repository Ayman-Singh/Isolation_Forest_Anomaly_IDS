#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

// Rule action
#define ACTION_PASS 0
#define ACTION_DROP 1


struct rule_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3]; // Padding for alignment
};

struct rule_value {
    __u32 action;
    __u64 counter; // Packet counter
};

struct packet_log {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  tcp_flags;
    __u8  pad[2];
    __u32 len;       // Packet length
    __u64 timestamp; // Timestamp in ns
};

#endif
