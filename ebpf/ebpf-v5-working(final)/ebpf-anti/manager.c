#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#define PIN_PATH "/sys/fs/bpf/xdp_firewall_map"
#define PIN_PATH_PERF "/sys/fs/bpf/xdp_packet_log"

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <cmd> [options]\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  load -i <iface>      Load and attach XDP program\n");
    fprintf(stderr, "  unload -i <iface>    Detach and unload\n");
    fprintf(stderr, "  add [options]        Add a rule\n");
    fprintf(stderr, "  del [options]        Delete a rule\n");
    fprintf(stderr, "  list                 List rules\n");
    fprintf(stderr, "\nRule Options:\n");
    fprintf(stderr, "  --src <ip>           Source IP\n");
    fprintf(stderr, "  --dst <ip>           Dest IP\n");
    fprintf(stderr, "  --sport <port>       Source Port\n");
    fprintf(stderr, "  --dport <port>       Dest Port\n");
    fprintf(stderr, "  --proto <tcp|udp>    Protocol\n");
    fprintf(stderr, "  --action <pass|drop> Action (default: drop)\n");
    fprintf(stderr, "  monitor              Monitor unmatched packets\n");
}

int do_load(const char *iface) {
    struct bpf_object *obj;
    int prog_fd, map_fd;
    int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    obj = bpf_object__open_file("xdp_prog.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_firewall_func"));
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL) < 0) {
        fprintf(stderr, "ERROR: bpf_xdp_attach failed\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "firewall_rules");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding map failed\n");
        return 1;
    }

    // Pin the map so we can access it later
    unlink(PIN_PATH); // Remove if exists
    if (bpf_obj_pin(map_fd, PIN_PATH) < 0) {
        fprintf(stderr, "ERROR: pinning map failed\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "packet_log_events");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding perf map failed\n");
        return 1;
    }

    unlink(PIN_PATH_PERF);
    if (bpf_obj_pin(map_fd, PIN_PATH_PERF) < 0) {
        fprintf(stderr, "ERROR: pinning perf map failed\n");
        return 1;
    }

    printf("Successfully loaded XDP program on %s\n", iface);
    return 0;
}

int do_unload(const char *iface) {
    int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    if (bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL) < 0) {
        fprintf(stderr, "ERROR: bpf_xdp_detach failed\n");
        return 1;
    }

    unlink(PIN_PATH);
    unlink(PIN_PATH_PERF);
    printf("Successfully unloaded XDP program from %s\n", iface);
    return 0;
}

void parse_rule_args(int argc, char **argv, struct rule_key *key, struct rule_value *val) {
    int opt;
    int option_index = 0;
    static struct option long_options[] = {
        {"src", required_argument, 0, 's'},
        {"dst", required_argument, 0, 'd'},
        {"sport", required_argument, 0, 'p'},
        {"dport", required_argument, 0, 'q'},
        {"proto", required_argument, 0, 'r'},
        {"action", required_argument, 0, 'a'},
        {0, 0, 0, 0}
    };

    memset(key, 0, sizeof(*key));
    memset(val, 0, sizeof(*val));
    val->action = ACTION_DROP; // Default

    while ((opt = getopt_long(argc, argv, "", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's': inet_pton(AF_INET, optarg, &key->src_ip); break;
            case 'd': inet_pton(AF_INET, optarg, &key->dst_ip); break;
            case 'p': key->src_port = htons(atoi(optarg)); break;
            case 'q': key->dst_port = htons(atoi(optarg)); break;
            case 'r':
                if (strcasecmp(optarg, "tcp") == 0) key->proto = IPPROTO_TCP;
                else if (strcasecmp(optarg, "udp") == 0) key->proto = IPPROTO_UDP;
                else if (strcasecmp(optarg, "icmp") == 0) key->proto = IPPROTO_ICMP;
                else key->proto = atoi(optarg);
                break;
            case 'a':
                if (strcasecmp(optarg, "pass") == 0) val->action = ACTION_PASS;
                else val->action = ACTION_DROP;
                break;
        }
    }
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct packet_log *e = data;
    FILE *fp = ctx;
    
    // Simple JSON format
    fprintf(fp, "{\"src_ip\": \"%d.%d.%d.%d\", \"dst_ip\": \"%d.%d.%d.%d\", \"src_port\": %d, \"dst_port\": %d, \"proto\": %d, \"tcp_flags\": %d, \"len\": %u, \"timestamp\": %llu}\n",
        e->src_ip & 0xFF, (e->src_ip >> 8) & 0xFF, (e->src_ip >> 16) & 0xFF, (e->src_ip >> 24) & 0xFF,
        e->dst_ip & 0xFF, (e->dst_ip >> 8) & 0xFF, (e->dst_ip >> 16) & 0xFF, (e->dst_ip >> 24) & 0xFF,
        ntohs(e->src_port), ntohs(e->dst_port), e->proto, e->tcp_flags, e->len, e->timestamp);
    fflush(fp);
}

int do_monitor() {
    struct bpf_object *obj;
    int map_fd;
    struct perf_buffer *pb = NULL;
    FILE *fp;

    // We need to load the object to find the map, but it might be already loaded.
    // However, to attach to perf buffer we need the map FD.
    // If we just want to attach to the existing map, we can try to find it by ID or path?
    // BPF_MAP_TYPE_PERF_EVENT_ARRAY usually needs to be pinned or we need to access the map from the loaded object.
    // Since we didn't pin the perf map in do_load, we might have an issue accessing it if we don't keep the object open.
    // Wait, the map is part of the object. If we reload the object, we get a new map unless we pinned it.
    // I should have pinned the perf map or use the same object.
    // Actually, standard practice is to pin the map if we want to access it from another process, OR use bpftool to pin it.
    // Let's modify do_load to pin the perf map as well.
    // For now, let's assume we need to modify do_load to pin 'packet_log_events'.
    
    // Let's rely on the user reloading the program or just pin it now in do_load.
    // I will update do_load in a separate step if needed, but for now let's assume it's pinned at /sys/fs/bpf/xdp_packet_log
    
    // Wait, I haven't pinned it in xdp_prog.c or do_load.
    // I need to update do_load to pin the perf map.
    // For this function, I will assume it is pinned.
    
    map_fd = bpf_obj_get(PIN_PATH_PERF);
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: opening pinned perf map failed. Is the XDP prog loaded?\n");
        return 1;
    }

    fp = fopen("firewall_log.json", "a");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    pb = perf_buffer__new(map_fd, 8, handle_event, NULL, fp, NULL);
    if (libbpf_get_error(pb)) {
        fprintf(stderr, "ERROR: failed to setup perf_buffer\n");
        return 1;
    }

    printf("Monitoring... (Press Ctrl+C to stop)\n");
    while (1) {
        perf_buffer__poll(pb, 100);
    }
    return 0;
}

int do_add(int argc, char **argv) {
    struct rule_key key;
    struct rule_value val;
    int map_fd;

    parse_rule_args(argc, argv, &key, &val);

    map_fd = bpf_obj_get(PIN_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: opening pinned map failed. Is the XDP prog loaded?\n");
        return 1;
    }

    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0) {
        perror("bpf_map_update_elem");
        return 1;
    }

    printf("Rule added\n");
    return 0;
}

int do_del(int argc, char **argv) {
    struct rule_key key;
    struct rule_value val; // unused for del
    int map_fd;

    parse_rule_args(argc, argv, &key, &val);

    map_fd = bpf_obj_get(PIN_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: opening pinned map failed\n");
        return 1;
    }

    if (bpf_map_delete_elem(map_fd, &key) < 0) {
        perror("bpf_map_delete_elem");
        return 1;
    }

    printf("Rule deleted\n");
    return 0;
}

int do_list() {
    int map_fd = bpf_obj_get(PIN_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: opening pinned map failed\n");
        return 1;
    }

    struct rule_key key = {}, next_key;
    struct rule_value val;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

    printf("%-16s %-16s %-6s %-6s %-5s %-5s %-10s\n", "SRC_IP", "DST_IP", "SPORT", "DPORT", "PROTO", "ACTION", "HITS");

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
            inet_ntop(AF_INET, &next_key.src_ip, src, sizeof(src));
            inet_ntop(AF_INET, &next_key.dst_ip, dst, sizeof(dst));
            printf("%-16s %-16s %-6d %-6d %-5d %-5s %-10llu\n",
                   src, dst, ntohs(next_key.src_port), ntohs(next_key.dst_port),
                   next_key.proto, val.action == ACTION_DROP ? "DROP" : "PASS", val.counter);
        }
        key = next_key;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "load") == 0) {
        if (argc < 4 || strcmp(argv[2], "-i") != 0) {
            usage(argv[0]);
            return 1;
        }
        return do_load(argv[3]);
    } else if (strcmp(argv[1], "unload") == 0) {
         if (argc < 4 || strcmp(argv[2], "-i") != 0) {
            usage(argv[0]);
            return 1;
        }
        return do_unload(argv[3]);
    } else if (strcmp(argv[1], "add") == 0) {
        return do_add(argc, argv);
    } else if (strcmp(argv[1], "del") == 0) {
        return do_del(argc, argv);
    } else if (strcmp(argv[1], "list") == 0) {
        return do_list();
    } else if (strcmp(argv[1], "monitor") == 0) {
        return do_monitor();
    } else {
        usage(argv[0]);
        return 1;
    }
}
