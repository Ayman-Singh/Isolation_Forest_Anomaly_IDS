# eBPF Firewall Walkthrough

## Overview
This project implements a minimal eBPF XDP firewall that allows dynamic rule updates without recompilation.

## Components
- `xdp_prog.c`: The kernel-side XDP program that enforces rules.
- `manager.c`: The userspace tool to manage rules and the XDP program.
- `common.h`: Shared definitions.
- `Makefile`: Build system.

## Build
```bash
make
```

## Usage

### 1. Load the Firewall
Attach the XDP program to an interface (e.g., `lo`).
```bash
sudo ./manager load -i lo
```

### 2. Add a Rule
Block ICMP traffic from 127.0.0.1 to 127.0.0.1.
```bash
sudo ./manager add --src 127.0.0.1 --dst 127.0.0.1 --proto icmp --action drop
```

### 3. Verify Blocking
Try to ping localhost.
```bash
ping -c 1 127.0.0.1
# Output: 100% packet loss
```

### 4. Check Stats
See the rule hits.
```bash
sudo ./manager list
# Output:
# SRC_IP           DST_IP           SPORT  DPORT  PROTO ACTION HITS      
# 127.0.0.1        127.0.0.1        0      0      1     DROP   1
```

### 5. Remove Rule
```bash
sudo ./manager del --src 127.0.0.1 --dst 127.0.0.1 --proto icmp
```

### 6. Verify Access
Ping should work now.
```bash
ping -c 1 127.0.0.1
# Output: 0% packet loss
```

### 7. Unload
```bash
sudo ./manager unload -i lo
```

### 8. JSON Logging
Unmatched packets are logged with their TCP flags to `firewall_log.json`.

#### Monitor Mode
Start monitoring in a separate terminal:
```bash
sudo ./manager monitor
# Logs written to firewall_log.json
```

#### Verify Logging
Generate traffic (e.g., using `nc` or `ping`) and check the logs:
```bash
nc -z -v -w 1 127.0.0.1 8080
grep "8080" firewall_log.json
# Output example: {"src_ip": "127.0.0.1", ... "tcp_flags": 2}
```
