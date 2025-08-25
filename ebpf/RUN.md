# Run the XDP eBPF pipeline

Prereqs (Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install -y bpfcc-tools python3-bpfcc clang llvm linux-headers-$(uname -r)
```

Optional (Python venv):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r ebpf/requirements.txt || true  # often system python3-bpfcc is used instead
```

Find your NIC:

```bash
ip -br link
```

Run (generic SKB mode for compatibility):

```bash
sudo -E python3 ebpf/xdp_loader.py --dev <IFACE> --mode generic --stdout
```

Stream to a Unix socket:

```bash
sudo -E python3 ebpf/xdp_loader.py --dev <IFACE> --mode native \
  --unix-sock /tmp/ids.sock --out-dir /var/log/xdp_ids
```

Notes:
- Use `--mode generic` if your NIC/driver doesn’t support native XDP.
- Use `--page-count` to adjust perf buffer size if you see lost events.
- Ctrl+C to stop; the loader detaches and prints stats.
