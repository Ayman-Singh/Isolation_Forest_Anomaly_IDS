#!/usr/bin/env python3
import argparse, os, signal, sys, time, json, atexit, ctypes
from ctypes import c_uint8, c_uint16, c_uint32, c_uint64, Structure
from bcc import BPF
try:
    # Older bcc exposes XDP flag constants on bcc.lib
    from bcc import lib as _bcc_lib
except Exception:
    _bcc_lib = None
from datetime import datetime
import socket

class FeatureEvent(Structure):
    _fields_ = [
        ("ts_ns", c_uint64),
        ("ip_version", c_uint8),
        ("protocol", c_uint8),
        ("tcp_flags", c_uint16),
        ("sport", c_uint16),
        ("dport", c_uint16),
        ("pkt_len", c_uint32),
        ("payload_len", c_uint32),
        ("tos", c_uint32),
    ]

PROTO_TCP, PROTO_UDP, PROTO_ICMP = 6, 17, 1

def flags_bits(flags):
    return {
        "tcp_fin": 1 if flags & 0x01 else 0,
        "tcp_syn": 1 if flags & 0x02 else 0,
        "tcp_rst": 1 if flags & 0x04 else 0,
        "tcp_psh": 1 if flags & 0x08 else 0,
        "tcp_ack": 1 if flags & 0x10 else 0,
        "tcp_urg": 1 if flags & 0x20 else 0,
        "tcp_ece": 1 if flags & 0x40 else 0,
        "tcp_cwr": 1 if flags & 0x80 else 0,
    }

def proto_onehot(p):
    return {
        "pr_tcp": 1 if p == PROTO_TCP else 0,
        "pr_udp": 1 if p == PROTO_UDP else 0,
        "pr_icmp": 1 if p == PROTO_ICMP else 0,
        "pr_other": 1 if p not in (PROTO_TCP, PROTO_UDP, PROTO_ICMP) else 0,
    }

class ModelSink:
    """Flexible sink for features: stdout, Unix socket, or NDJSON files."""

    def __init__(self, out_dir: str | None, batch_size: int = 1024, unix_sock: str | None = None, to_stdout: bool = False):
        self.out_dir = out_dir
        self.unix_sock_path = unix_sock
        self.to_stdout = to_stdout
        if self.out_dir:
            os.makedirs(self.out_dir, exist_ok=True)
        self.batch = []
        self.batch_size = max(1, batch_size)
        self.sock = None
        if self.unix_sock_path:
            self._connect_socket()

    def _connect_socket(self):
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(1.0)
            self.sock.connect(self.unix_sock_path)
        except Exception as e:
            sys.stderr.write(f"[sink] failed to connect to unix socket {self.unix_sock_path}: {e}\n")
            self.sock = None

    def handle(self, feat: dict):
        self.batch.append(feat)
        if len(self.batch) >= self.batch_size:
            self.flush()

    def _send_stdout(self, items):
        for item in items:
            sys.stdout.write(json.dumps(item) + "\n")
        sys.stdout.flush()

    def _send_socket(self, items):
        if not self.sock:
            self._connect_socket()
            if not self.sock:
                return False
        try:
            for item in items:
                line = json.dumps(item).encode() + b"\n"
                self.sock.sendall(line)
            return True
        except Exception as e:
            sys.stderr.write(f"[sink] socket send error: {e}\n")
            try:
                if self.sock:
                    self.sock.close()
            finally:
                self.sock = None
            return False

    def _write_files(self, items):
        if not self.out_dir:
            return
        path = os.path.join(self.out_dir, f"xdp_batch_{int(time.time())}.ndjson")
        with open(path, "a") as f:
            for item in items:
                f.write(json.dumps(item) + "\n")

    def flush(self):
        if not self.batch:
            return
        items = self.batch
        self.batch = []
        if self.to_stdout:
            self._send_stdout(items)
        sent = False
        if self.unix_sock_path:
            sent = self._send_socket(items)
        if self.out_dir and (self.to_stdout or not self.unix_sock_path or not sent):
            # Always persist if stdout is enabled; otherwise fallback if socket not configured or failed
            self._write_files(items)

    def close(self):
        self.flush()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

XDP_PROG = None

def build_bpf():
    global XDP_PROG
    kern_path = os.path.join(os.path.dirname(__file__), "xdp_ids_kern.c")
    with open(kern_path, "r") as f:
        src = f.read()
    XDP_PROG = BPF(text=src)
    return XDP_PROG


def attach(dev: str):
    prog = XDP_PROG.load_func("xdp_ids", BPF.XDP)
    XDP_PROG.attach_xdp(dev, prog, 0)


def detach(dev: str):
    try:
        XDP_PROG.remove_xdp(dev, 0)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="XDP eBPF IDS pipeline")
    ap.add_argument("--dev", required=True, help="Network interface (NIC)")
    ap.add_argument("--out-dir", default="/tmp/xdp_features", help="NDJSON output directory (fallback or archive)")
    ap.add_argument("--batch", type=int, default=1024, help="Batch size for flushing")
    ap.add_argument("--unix-sock", default=None, help="Unix domain socket to stream JSON lines to a model server")
    ap.add_argument("--stdout", action="store_true", help="Also mirror JSON to stdout")
    ap.add_argument("--mode", choices=["generic", "native"], default="native", help="XDP attach mode: generic (skb) or native (driver)")
    ap.add_argument("--page-count", type=int, default=64, help="Perf buffer page count per CPU")
    args = ap.parse_args()

    bpf = build_bpf()
    # Attach XDP with chosen mode
    prog = XDP_PROG.load_func("xdp_ids", BPF.XDP)
    # Resolve XDP flags across bcc versions
    if _bcc_lib is not None:
        XDP_FLAGS_SKB_MODE = getattr(_bcc_lib, "XDP_FLAGS_SKB_MODE", 0)
        XDP_FLAGS_DRV_MODE = getattr(_bcc_lib, "XDP_FLAGS_DRV_MODE", 0)
    else:
        XDP_FLAGS_SKB_MODE = getattr(BPF, "XDP_FLAGS_SKB_MODE", 0)
        XDP_FLAGS_DRV_MODE = getattr(BPF, "XDP_FLAGS_DRV_MODE", 0)
    flags = XDP_FLAGS_SKB_MODE if args.mode == "generic" else XDP_FLAGS_DRV_MODE
    XDP_PROG.attach_xdp(args.dev, prog, flags)
    events = bpf.get_table("events")
    sink = ModelSink(args.out_dir, args.batch, unix_sock=args.unix_sock, to_stdout=args.stdout)

    # Simple stats
    stats = {"recv": 0, "lost": 0, "t0": time.time()}

    def handle_event(cpu, data, size):
        ev = ctypes.cast(data, ctypes.POINTER(FeatureEvent)).contents
        proto = proto_onehot(int(ev.protocol))
        flags = flags_bits(int(ev.tcp_flags))
        feat = {
            "timestamp_ns": int(getattr(ev, "ts_ns", 0)),
            "ip_version": int(getattr(ev, "ip_version", 0)),
            "protocol": int(getattr(ev, "protocol", 0)),
            **proto,
            **flags,
            "src_port": int(getattr(ev, "sport", 0)),
            "dst_port": int(getattr(ev, "dport", 0)),
            "pkt_len": int(getattr(ev, "pkt_len", 0)),
            "payload_len": int(getattr(ev, "payload_len", 0)),
            "tos": int(getattr(ev, "tos", 0)),
        }
        # Optional port bins to mirror preprocessor
        feat.update({
            "src_port_low": 1 if feat["src_port"] < 1024 else 0,
            "src_port_mid": 1 if 1024 <= feat["src_port"] <= 49151 else 0,
            "src_port_high": 1 if feat["src_port"] > 49151 else 0,
            "dst_port_low": 1 if feat["dst_port"] < 1024 else 0,
            "dst_port_mid": 1 if 1024 <= feat["dst_port"] <= 49151 else 0,
            "dst_port_high": 1 if feat["dst_port"] > 49151 else 0,
        })
        sink.handle(feat)
        stats["recv"] += 1

    def handle_lost(cpu, lost):
        # In production, log/metrics; here we print a warning
        sys.stderr.write(f"[perf] lost {lost} events on CPU {cpu}\n")
        stats["lost"] += lost

    events.open_perf_buffer(handle_event, lost_cb=handle_lost, page_cnt=max(8, args.page_count))

    def shutdown(signum, frame):
        sink.close()
        try:
            XDP_PROG.remove_xdp(args.dev, flags)
        except Exception:
            pass
        dt = max(1e-9, time.time() - stats["t0"])
        rate = stats["recv"] / dt
        sys.stderr.write(f"[stats] recv={stats['recv']} lost={stats['lost']} rate={rate:.1f} ev/s uptime={dt:.1f}s\n")
        sys.exit(0)

    atexit.register(lambda: shutdown(None, None))
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while True:
            bpf.perf_buffer_poll(timeout=1000)
    finally:
        shutdown(None, None)

if __name__ == "__main__":
    main()
