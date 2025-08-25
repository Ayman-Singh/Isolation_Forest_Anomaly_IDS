# eBPF XDP pipeline for real-time IDS

Production-grade XDP program extracts packet features at the NIC and streams them to user space with minimal overhead. The user-space loader batches and forwards features to a model over a Unix socket or writes NDJSON files.

## Components
- `xdp_ids_kern.c`: XDP program attached to a NIC; extracts per-packet features and pushes to a perf ring buffer.
- `xdp_loader.py`: User-space loader (BCC) that attaches the XDP program, consumes events, batches features, and ships them to your model (stdout, Unix socket, or NDJSON files).

## Requirements
- Linux kernel with eBPF/XDP support and root privileges to attach XDP.
- bcc (Python) and clang/llvm for compiling the eBPF program.
- Python 3.10+ recommended.

Install Python deps (bcc binding version may vary by distro):

```
pip install -r ebpf/requirements.txt  # or install system bcc-python package
```

On Ubuntu/Debian, system packages:

```
sudo apt-get update
sudo apt-get install -y bpfcc-tools libbpf-dev linux-headers-$(uname -r) clang llvm python3-bpfcc
```

## Usage
Identify your NIC (e.g., `eth0`, `ens5`):

```
ip -br link
```

Run the loader (requires sudo):

```
sudo python3 ebpf/xdp_loader.py --dev eth0 --stdout
```

Stream to a Unix domain socket (recommended for production):

```
sudo python3 ebpf/xdp_loader.py --dev eth0 --unix-sock /tmp/ids.sock --out-dir /var/log/xdp_ids
```

The loader maintains simple statistics and supports graceful shutdown (Ctrl+C).

## Feature schema (per packet)
Fields emitted as JSON lines:
- timestamp_ns, ip_version, protocol, pr_tcp, pr_udp, pr_icmp, pr_other
- tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg, tcp_ece, tcp_cwr
- src_port, src_port_low/mid/high, dst_port, dst_port_low/mid/high
- pkt_len, payload_len, tos

Adjust or extend features in `xdp_ids_kern.c` and the mapping in `xdp_loader.py` to match your training/preprocessing.

## Minimal model integration
Example Python server to receive features via Unix socket and score with your Isolation Forest:

```python
import json, socket, os
sock_path = "/tmp/ids.sock"
try:
    os.unlink(sock_path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(1)
conn, _ = s.accept()
buf = b""
while True:
    data = conn.recv(8192)
    if not data: break
    buf += data
    while b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        feat = json.loads(line.decode())
        # TODO: vectorize and call model.score_samples([...])
        # print(feat)
```

## Notes
- The XDP program returns XDP_PASS, so it does not alter or drop traffic.
- If you observe lost events, lower the batch size, ensure the perf buffer is being drained fast enough, or consider using a ring/per-CPU array with a user-space poller.
- Ensure your kernel and user-space bcc versions are compatible.
