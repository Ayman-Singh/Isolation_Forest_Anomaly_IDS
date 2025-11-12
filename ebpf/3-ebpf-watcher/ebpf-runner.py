#!/usr/bin/env python3
"""
ebpf-runner.py

Attaches the feature-extraction XDP program, streams feature events, and offers a
simple command loop to manage the in-kernel rule table and (future) ML verdicts.
"""

from __future__ import annotations

import argparse
import ctypes
import math
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, Tuple

try:
    from bcc import BPF  # type: ignore[import-not-found]
except ImportError as exc:  # pragma: no cover - environment specific
    raise SystemExit("The 'bcc' Python package is required to run this script.") from exc


MAX_RULES = 64
ACTION_PASS = 0
ACTION_DROP = 1

TCP_FLAG_NAMES: Dict[int, str] = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
}


class FlowKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("proto", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]


class FeatureEvent(ctypes.Structure):
    _fields_ = [
        ("key", FlowKey),
        ("duration_ns", ctypes.c_uint64),
        ("packets", ctypes.c_uint64),
        ("bytes", ctypes.c_uint64),
        ("bps", ctypes.c_uint64),
        ("pps", ctypes.c_uint64),
        ("tcp_flags", ctypes.c_uint32),
        ("log2_bytes", ctypes.c_uint32),
        ("log2_packets", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("tcp", ctypes.c_uint8),
        ("udp", ctypes.c_uint8),
        ("icmp", ctypes.c_uint8),
        ("src_port_low", ctypes.c_uint8),
        ("src_port_high", ctypes.c_uint8),
        ("dst_port_low", ctypes.c_uint8),
        ("dst_port_high", ctypes.c_uint8),
    ]


class Rule(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint32),
        ("priority", ctypes.c_uint32),
        ("src_ip", ctypes.c_uint32),
        ("src_ip_mask", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("dst_ip_mask", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("src_port_mask", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("dst_port_mask", ctypes.c_uint16),
        ("proto", ctypes.c_uint8),
        ("proto_mask", ctypes.c_uint8),
        ("action", ctypes.c_uint8),
        ("active", ctypes.c_uint8),
        ("min_packets", ctypes.c_uint64),
        ("max_packets", ctypes.c_uint64),
        ("min_bytes", ctypes.c_uint64),
        ("max_bytes", ctypes.c_uint64),
        ("min_bps", ctypes.c_uint64),
        ("max_bps", ctypes.c_uint64),
        ("min_pps", ctypes.c_uint64),
        ("max_pps", ctypes.c_uint64),
        ("required_flags", ctypes.c_uint32),
        ("forbidden_flags", ctypes.c_uint32),
    ]


class MLDecision(ctypes.Structure):
    _fields_ = [
        ("action", ctypes.c_uint8),
        ("confidence", ctypes.c_uint8),
        ("reserved", ctypes.c_uint16),
        ("expires_ns", ctypes.c_uint64),
    ]


def inet_aton(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def mask_from_prefix(prefix: int) -> int:
    if prefix <= 0:
        return 0
    if prefix >= 32:
        return 0xFFFFFFFF
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return socket.htonl(mask)


def prefix_from_mask(mask: int) -> int:
    if mask == 0:
        return 0
    host_mask = socket.ntohl(mask)
    prefix = 0
    while host_mask & 0x80000000:
        prefix += 1
        host_mask = (host_mask << 1) & 0xFFFFFFFF
    return prefix


def flags_to_str(mask: int) -> str:
    if not mask:
        return "-"
    parts = [name for bit, name in TCP_FLAG_NAMES.items() if mask & bit]
    return ",".join(parts) if parts else "-"


def build_rule_from_args(rule_id: int, args: Dict[str, str]) -> Rule:
    rule = Rule()
    rule.id = rule_id
    rule.priority = int(args.get("priority", 1000))

    src = args.get("src", "0.0.0.0/0")
    dst = args.get("dst", "0.0.0.0/0")
    rule.src_ip, rule.src_ip_mask = parse_cidr(src)
    rule.dst_ip, rule.dst_ip_mask = parse_cidr(dst)

    rule.src_port = int(args.get("sport", 0))
    rule.dst_port = int(args.get("dport", 0))
    rule.src_port_mask = 0xFFFF if rule.src_port else 0
    rule.dst_port_mask = 0xFFFF if rule.dst_port else 0

    proto = args.get("proto", "any").lower()
    proto_lookup = {"any": 0, "tcp": 6, "udp": 17, "icmp": 1}
    if proto not in proto_lookup:
        raise ValueError(f"Unsupported proto '{proto}'")
    rule.proto = proto_lookup[proto]
    rule.proto_mask = 0xFF if rule.proto else 0

    action = args.get("action", "pass").lower()
    if action not in {"pass", "drop"}:
        raise ValueError("action must be 'pass' or 'drop'")
    rule.action = ACTION_DROP if action == "drop" else ACTION_PASS
    rule.active = 1

    rule.min_packets = int(args.get("min_packets", 0))
    rule.max_packets = int(args.get("max_packets", 0))
    rule.min_bytes = int(args.get("min_bytes", 0))
    rule.max_bytes = int(args.get("max_bytes", 0))
    rule.min_bps = int(args.get("min_bps", 0))
    rule.max_bps = int(args.get("max_bps", 0))
    rule.min_pps = int(args.get("min_pps", 0))
    rule.max_pps = int(args.get("max_pps", 0))

    require = args.get("require_flags", "").upper()
    forbid = args.get("forbid_flags", "").upper()
    rule.required_flags = flags_from_string(require)
    rule.forbidden_flags = flags_from_string(forbid)

    return rule


def flags_from_string(flag_csv: str) -> int:
    if not flag_csv:
        return 0
    mask = 0
    for token in flag_csv.split(","):
        token = token.strip()
        if not token:
            continue
        inverse = {v: k for k, v in TCP_FLAG_NAMES.items()}
        bit = inverse.get(token)
        if bit is None:
            raise ValueError(f"Unknown TCP flag '{token}'")
        mask |= bit
    return mask


def parse_cidr(expr: str) -> Tuple[int, int]:
    expr = expr.strip()
    if expr in {"any", ""}:
        return 0, 0
    try:
        ip, prefix = expr.split("/")
        prefix_val = int(prefix)
    except ValueError:
        ip = expr
        prefix_val = 32
    return inet_aton(ip), mask_from_prefix(prefix_val)


class XDPFeatureRunner:
    def __init__(self, interface: str):
        self.interface = interface
        src = Path(__file__).with_name("ebpf-probe.c").read_text()
        self.bpf = BPF(text=src)
        self.fn = self.bpf.load_func("xdp_feature_guard", BPF.XDP)
        self.stop = threading.Event()

    def attach(self) -> None:
        self.bpf.attach_xdp(self.interface, self.fn, 0)

    def detach(self) -> None:
        try:
            self.bpf.remove_xdp(self.interface, 0)
        except Exception:
            pass

    def rules_table(self):
        return self.bpf.get_table("rules_map")

    def decision_table(self):
        return self.bpf.get_table("ml_decision_map")

    def flow_table(self):
        return self.bpf.get_table("flow_state_map")

    def run(self) -> None:
        events = self.bpf["feature_events"]
        events.open_perf_buffer(handle_event)
        print("Feature stream active. Type commands like 'rule add id=1 src=10.0.0.0/24 proto=tcp action=drop'.")
        print("Commands: rule add|del|list, ml set|del, stats, help, quit")

        command_thread = threading.Thread(target=self.command_loop, daemon=True)
        command_thread.start()

        while not self.stop.is_set():
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                self.stop.set()

    def command_loop(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            if line in {"quit", "exit"}:
                self.stop.set()
                break
            if line == "help":
                print("rule add id=<n> src=<cidr> dst=<cidr> sport=<n> dport=<n> proto=<any|tcp|udp|icmp> action=<pass|drop> [priority=<n>]")
                print("rule del id=<n>")
                print("rule list")
                print("ml set id=<n> src=<cidr> dst=<cidr> sport=<n> dport=<n> proto=<...> action=<pass|drop> [ttl=<seconds>]")
                print("ml del id=<n>")
                print("stats")
                continue
            try:
                self.process_command(line)
            except Exception as exc:
                print(f"Command error: {exc}")

    def process_command(self, line: str) -> None:
        tokens = line.split()
        if not tokens:
            return
        cmd = tokens[0].lower()
        args = tokens[1:]

        if cmd == "rule":
            self.handle_rule(args)
        elif cmd == "ml":
            self.handle_ml(args)
        elif cmd == "stats":
            self.print_stats()
        else:
            print(f"Unknown command '{cmd}'")

    def handle_rule(self, args: Iterable[str]) -> None:
        args = list(args)
        if not args:
            raise ValueError("rule command requires subcommand")
        sub = args[0].lower()
        kv = parse_kv_pairs(args[1:])

        if sub == "add":
            if "id" not in kv:
                raise ValueError("rule add requires id=<int>")
            rule_id = int(kv.pop("id"))
            if rule_id < 0 or rule_id >= MAX_RULES:
                raise ValueError(f"id must be in [0,{MAX_RULES - 1}]")
            rule = build_rule_from_args(rule_id, kv)
            self.rules_table()[ctypes.c_uint(rule_id)] = rule
            print(f"Rule {rule_id} updated: action={'DROP' if rule.action else 'PASS'} priority={rule.priority}")
        elif sub == "del":
            if not kv.get("id"):
                raise ValueError("rule del requires id=<int>")
            rule_id = int(kv["id"])
            zero = Rule()
            self.rules_table()[ctypes.c_uint(rule_id)] = zero
            print(f"Rule {rule_id} cleared")
        elif sub == "list":
            self.list_rules()
        else:
            raise ValueError(f"unknown rule subcommand '{sub}'")

    def handle_ml(self, args: Iterable[str]) -> None:
        args = list(args)
        if not args:
            raise ValueError("ml command requires subcommand")
        sub = args[0].lower()
        kv = parse_kv_pairs(args[1:])

        if sub == "set":
            key = flow_key_from_args(kv)
            decision = MLDecision()
            action = kv.get("action", "pass").lower()
            if action not in {"pass", "drop"}:
                raise ValueError("ml set action must be pass/drop")
            decision.action = ACTION_DROP if action == "drop" else ACTION_PASS
            ttl = float(kv.get("ttl", 30))
            decision.expires_ns = int((time.time() + ttl) * 1e9)
            self.decision_table()[key] = decision
            print("ML verdict stored for flow")
        elif sub == "del":
            key = flow_key_from_args(kv)
            try:
                del self.decision_table()[key]
                print("ML verdict cleared")
            except KeyError:
                print("No ML verdict for key")
        else:
            raise ValueError(f"unknown ml subcommand '{sub}'")

    def list_rules(self) -> None:
        table = self.rules_table()
        print("Active rules:")
        for idx in range(MAX_RULES):
            key = ctypes.c_uint(idx)
            rule = table[key]
            if not rule.active:
                continue
            src = f"{inet_ntoa(rule.src_ip)}/{prefix_from_mask(rule.src_ip_mask)}"
            dst = f"{inet_ntoa(rule.dst_ip)}/{prefix_from_mask(rule.dst_ip_mask)}"
            proto = rule.proto if rule.proto_mask else 0
            proto_name = {0: "ANY", 6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
            print(
                f"  id={idx} prio={rule.priority} {proto_name} {src}->{dst} sport={rule.src_port or '*'} dport={rule.dst_port or '*'} "
                f"action={'DROP' if rule.action else 'PASS'} min_pkts={rule.min_packets or '-'} max_pkts={rule.max_packets or '-'} "
                f"min_bytes={rule.min_bytes or '-'} max_bytes={rule.max_bytes or '-'} req_flags={flags_to_str(rule.required_flags)}"
            )

    def print_stats(self) -> None:
        flows = self.flow_table()
        count = 0
        for _ in flows.keys():
            count += 1
        print(f"Tracked flows: {count}")


def parse_kv_pairs(parts: Iterable[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for token in parts:
        if "=" not in token:
            raise ValueError(f"Expected key=value, got '{token}'")
        key, value = token.split("=", 1)
        result[key.lower()] = value
    return result


def inet_ntoa(value: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", value)) if value else "0.0.0.0"


def flow_key_from_args(args: Dict[str, str]) -> FlowKey:
    key = FlowKey()
    src_expr = args.get("src", "0.0.0.0")
    dst_expr = args.get("dst", "0.0.0.0")
    key.src_ip = parse_cidr(src_expr)[0]
    key.dst_ip = parse_cidr(dst_expr)[0]
    key.src_port = int(args.get("sport", 0))
    key.dst_port = int(args.get("dport", 0))
    proto = args.get("proto", "any").lower()
    key.proto = {"any": 0, "tcp": 6, "udp": 17, "icmp": 1}.get(proto, 0)
    return key


def tcp_flags_to_list(mask: int) -> Iterable[str]:
    for bit, name in TCP_FLAG_NAMES.items():
        if mask & bit:
            yield name


def handle_event(cpu: int, data, size: int) -> None:
    event = ctypes.cast(data, ctypes.POINTER(FeatureEvent)).contents  # type: ignore[arg-type]
    duration = event.duration_ns / 1e9
    features = {
        "src_ip": inet_ntoa(event.key.src_ip),
        "dst_ip": inet_ntoa(event.key.dst_ip),
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "proto": event.key.proto,
        "duration": duration,
        "packets": event.packets,
        "bytes": event.bytes,
        "bps": event.bps,
        "pps": event.pps,
        "log_bytes": math.log1p(event.bytes),
        "log_packets": math.log1p(event.packets),
        "tcp": int(event.tcp),
        "udp": int(event.udp),
        "icmp": int(event.icmp),
        "fin": int(bool(event.tcp_flags & 0x01)),
        "syn": int(bool(event.tcp_flags & 0x02)),
        "rst": int(bool(event.tcp_flags & 0x04)),
        "psh": int(bool(event.tcp_flags & 0x08)),
        "ack": int(bool(event.tcp_flags & 0x10)),
        "urg": int(bool(event.tcp_flags & 0x20)),
        "src_low": int(event.src_port_low),
        "src_high": int(event.src_port_high),
        "dst_low": int(event.dst_port_low),
        "dst_high": int(event.dst_port_high),
    }
    print("ML features:", features)


def install_signals(runner: XDPFeatureRunner) -> None:
    def handler(signum, frame):
        runner.stop.set()

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Attach XDP feature extractor and manage rules")
    parser.add_argument("--interface", "-i", required=True, help="Network interface for the XDP program")
    args = parser.parse_args()

    runner = XDPFeatureRunner(args.interface)
    install_signals(runner)

    runner.attach()
    try:
        runner.run()
    finally:
        runner.detach()


if __name__ == "__main__":
    main()
