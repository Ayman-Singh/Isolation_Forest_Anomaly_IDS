# eBPF XDP Firewall with ML-Based Anomaly Detection

An XDP-based firewall that uses machine learning to detect and block anomalous network traffic. The system logs unmatched packets, aggregates them into flows, and uses an Isolation Forest model to classify traffic as normal or anomalous.

## Architecture

```
┌─────────────────┐
│  Network Traffic│
└────────┬────────┘
         │
    ┌────▼─────┐
    │ XDP Hook │  (Kernel Space)
    │xdp_prog.c│
    └────┬─────┘
         │
    ┌────▼──────────┐
    │ BPF Hash Map  │  (firewall_rules)
    │ 5-tuple → ACL │
    └────┬──────────┘
         │
    ┌────▼─────────────┐
    │ Perf Event Array │  (packet_log_events)
    │  Unmatched Pkts  │
    └────┬─────────────┘
         │
    ┌────▼────────┐
    │  manager.c  │  (User Space)
    │   monitor   │
    └────┬────────┘
         │
    ┌────▼──────────────┐
    │firewall_log.json  │
    │ {len, timestamp}  │
    └────┬──────────────┘
         │
    ┌────▼─────────────────────┐
    │import_firewall_rules.py  │
    │  Flow Aggregation        │
    │  ML Prediction           │
    └────┬─────────────────────┘
         │
    ┌────▼────────┐
    │ Add Rules   │
    │ to BPF Map  │
    └─────────────┘
```

## Components

### 1. XDP Program (`xdp_prog.c`)
- **Purpose**: Packet filtering at the kernel level
- **Features**:
  - Parses Ethernet, IPv4, TCP/UDP/ICMP headers
  - Performs 5-tuple lookup in BPF hash map
  - Logs unmatched packets with length and timestamp
  - Increments hit counters for matched rules

### 2. Manager (`manager.c`)
- **Purpose**: Control plane for XDP program
- **Commands**:
  - `load -i <iface>`: Load XDP program on interface
  - `unload -i <iface>`: Unload XDP program
  - `add`: Add firewall rule
  - `del`: Delete firewall rule
  - `list`: List all rules with hit counters
  - `monitor`: Capture unmatched packets to `firewall_log.json`

### 3. ML Analyzer (`import_firewall_rules.py`)
- **Purpose**: Analyze traffic and generate firewall rules
- **Features**:
  - Aggregates packets into flows by 5-tuple
  - Calculates session features (duration, packets, bytes, bps, pps)
  - Uses Isolation Forest model for anomaly detection
  - Generates and optionally applies firewall rules

## Usage Guide

### Prerequisites

```bash
# Install dependencies
sudo apt install clang libbpf-dev

# Create Python virtual environment
python3 -m venv venv
./venv/bin/pip install numpy pandas joblib scikit-learn
```

### Build

```bash
make clean && make all
```

### 1. Load XDP Program

```bash
# Load on loopback interface (for testing)
sudo ./manager load -i lo

# Load on physical interface (for production)
sudo ./manager load -i enp0s3
```

**Purpose**: Attaches the XDP program to the specified network interface and pins the BPF maps for access.

---

### 2. Monitor Traffic

```bash
sudo ./manager monitor
```

**Purpose**: Captures unmatched packets (those not matching any firewall rule) and writes them to `firewall_log.json` with the following fields:
- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`
- `tcp_flags` (for TCP packets)
- `len` (packet length in bytes)
- `timestamp` (nanoseconds since boot)

**Note**: Press `Ctrl+C` to stop monitoring.

---

### 3. Analyze Traffic (Dry Run)

```bash
./venv/bin/python3 import_firewall_rules.py --file firewall_log.json --no-sudo
```

**Purpose**: 
- Reads `firewall_log.json`
- Aggregates packets into flows by 5-tuple
- Calculates session features:
  - `packets`: Count of packets in flow
  - `bytes`: Sum of packet lengths
  - `duration`: Time between first and last packet (seconds)
  - `bps`: Bytes per packet
  - `pps`: Packets per second
- Runs ML model to classify each flow as NORMAL (PASS) or ANOMALY (DROP)
- Writes commands to `ml_firewall_commands.json` (does NOT execute them)

**Output Example**:
```
[1/29] 142.250.193.74:443 → 10.0.2.15:33404 (tcp) | Pkts: 1, Bytes: 60, Dur: 0.0010s | Score: -0.0430 | NORMAL → PASS
[4/29] 142.250.183.234:443 → 10.0.2.15:40616 (udp) | Pkts: 1, Bytes: 203, Dur: 0.0010s | Score: -0.0981 | ANOMALY → DROP
```

---

### 4. Apply Firewall Rules

```bash
./venv/bin/python3 import_firewall_rules.py --file firewall_log.json --apply
```

**Purpose**: Same as dry run, but **executes** the generated commands using `sudo ./manager add`, which adds rules to the BPF map.

**What happens**:
- NORMAL flows → `--action pass` rules added
- ANOMALY flows → `--action drop` rules added

---

### 5. List Active Rules

```bash
sudo ./manager list
```

**Purpose**: Displays all active firewall rules with their hit counters.

**Output Example**:
```
SRC_IP           DST_IP           SPORT  DPORT  PROTO ACTION HITS      
64.233.170.81    10.0.2.15        443    34424  6     PASS  1         
142.250.183.234  10.0.2.15        443    40616  17    DROP  5         
```

**Hit Counter**: Shows how many packets matched each rule.

---

### 6. Unload XDP Program

```bash
sudo ./manager unload -i <iface>
```

**Purpose**: Detaches the XDP program from the interface and unpins the BPF maps.

---

## Workflow Example

### Complete End-to-End Workflow

```bash
# 1. Clean up and reload XDP program
sudo rm -f firewall_log.json
sudo ./manager unload -i enp0s3
sudo ./manager load -i enp0s3

# 2. Monitor traffic for 30 seconds
sudo timeout 30s ./manager monitor

# 3. Analyze captured traffic (dry run)
./venv/bin/python3 import_firewall_rules.py --file firewall_log.json --no-sudo

# 4. Apply ML-generated rules
./venv/bin/python3 import_firewall_rules.py --file firewall_log.json --apply

# 5. Verify rules are active
sudo ./manager list
```

---

## Testing with ICMP

```bash
# Generate ICMP traffic
ping -c 5 -i 0.2 127.0.0.1 > /dev/null &

# Monitor in foreground
sudo timeout 5s ./manager monitor

# Analyze
./venv/bin/python3 import_firewall_rules.py --file firewall_log.json --no-sudo | grep "(icmp)"
```

**Expected Output**:
```
[9/11] 127.0.0.1:0 → 127.0.0.1:0 (icmp) | Pkts: 5, Bytes: 490, Dur: 0.8000s | Score: -0.1974 | ANOMALY → DROP
```

This shows the ICMP flow was aggregated (5 packets) and classified as an anomaly.

---

## Utility Scripts

### Check Unique Flows

```bash
python3 check_unique.py
```

**Purpose**: Analyzes `firewall_log.json` to count:
- Total packets logged
- Unique flows (5-tuple combinations)
- Top flows by packet count

**Output Example**:
```
Total packets in log: 681
Unique flows (5-tuple): 29

Top 10 flows by packet count:
1. 34.54.84.110:443 → 10.0.2.15:58438 (TCP): 91 packets
2. 64.233.170.81:443 → 10.0.2.15:34276 (TCP): 55 packets
```

---

## Key Features

### Session Feature Extraction
The system extracts the following session-based features for ML analysis:

| Feature | Description | Calculation |
|---------|-------------|-------------|
| `duration` | Flow duration in seconds | `(last_timestamp - first_timestamp) / 1e9` |
| `packets` | Total packets in flow | Count of packets with same 5-tuple |
| `bytes` | Total bytes in flow | Sum of `len` field |
| `bps` | Bytes per packet | `bytes / packets` |
| `pps` | Packets per second | `packets / duration` |
| `log_bytes` | Log-transformed bytes | `log1p(bytes)` |
| `log_packets` | Log-transformed packets | `log1p(packets)` |
| TCP flags | SYN, ACK, FIN, RST, PSH, URG | Bitwise OR of all packets |
| Port features | `src_low`, `src_high`, `dst_low`, `dst_high` | Boolean port range indicators |

### ML Model
- **Algorithm**: Isolation Forest (unsupervised anomaly detection)
- **Threshold**: -0.093570 (configurable in `import_firewall_rules.py`)
- **Input**: 22 features per flow
- **Output**: Anomaly score and binary classification (0=NORMAL, 1=ANOMALY)

---

## Troubleshooting

### Python Module Not Found
```bash
# Error: ModuleNotFoundError: No module named 'numpy'
# Solution: Use virtual environment
./venv/bin/python3 import_firewall_rules.py --file firewall_log.json --no-sudo
```

### No Log File Created
```bash
# Issue: firewall_log.json not created after monitoring
# Cause: No unmatched packets (all traffic matched existing rules)
# Solution: Clear rules first
sudo ./manager unload -i <iface>
sudo ./manager load -i <iface>
```

### Permission Denied
```bash
# Issue: Permission denied when accessing firewall_log.json
# Cause: File owned by root
# Solution: Use sudo or change ownership
sudo chown $USER:$USER firewall_log.json
```

---

## Files

| File | Purpose |
|------|---------|
| `xdp_prog.c` | XDP packet filter (kernel space) |
| `manager.c` | Control plane (user space) |
| `common.h` | Shared data structures |
| `import_firewall_rules.py` | ML analyzer and rule generator |
| `check_unique.py` | Flow statistics utility |
| `firewall_log.json` | Packet log (generated by monitor) |
| `ml_firewall_commands.json` | Generated commands (output) |
| `ugr16_if_stream_ms16384_20251003_181922.joblib` | Pre-trained ML model |

---

## License

GPL
