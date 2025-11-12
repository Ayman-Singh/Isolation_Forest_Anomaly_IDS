#!/usr/bin/env python3
"""
xdp_tool.py - small utility to manage rules for xdp_fw eBPF program.

Usage:
  python3 xdp_tool.py pin-maps <iface>      # pins maps created by loaded object into /sys/fs/bpf/
  python3 xdp_tool.py unpin-maps
  python3 xdp_tool.py list
  python3 xdp_tool.py add --json rule.json   # requires "id" field (0..MAX_RULES-1) in JSON
  python3 xdp_tool.py delete <rule_id>
  python3 xdp_tool.py set-default-action <FORWARD|DROP>

Note: This tool calls 'bpftool' (must be installed) and writes binary key/value files to pass to bpftool.
"""
import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

BPFTOOL = shutil.which("bpftool")
if not BPFTOOL:
    print("ERROR: bpftool not found; please install 'bpftool' (apt install bpftool).", file=sys.stderr)
    sys.exit(1)

PIN_RULES = "/sys/fs/bpf/xdp_fw_rules"
PIN_META = "/sys/fs/bpf/xdp_fw_meta"
MAX_RULES = 128

def run(cmd):
    # simple wrapper
    print("+", " ".join(cmd))
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        print("ERROR:", r.stderr.strip(), file=sys.stderr)
    return r

def pin_maps(iface):
    # list maps for the pinned XDP program on iface using bpftool prog show
    # find maps from program attached to iface XDP
    r = run([BPFTOOL, "net", "show"])
    # Simpler: user should load with: ip link set dev <iface> xdp obj xdp_fw.o sec xdp
    # Then use: bpftool map show to find map ids and pin them.
    # We'll show existing maps and instruct user how to pin manually if not found.
    print("Attempting to auto-pin maps by searching for map names 'rules_map' and 'meta_map'.")
    # Search existing maps and pin by id if not already pinned
    r = run([BPFTOOL, "map", "show"])
    out = r.stdout
    # parse lines like: "map 0: name rules_map type ARRAY ..."
    to_pin = {}
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) < 3: continue
        if parts[0] != "map": continue
        # get id
        mid = parts[1].rstrip(':')
        name = None
        for p in parts:
            if p.startswith("name"):
                # name=rules_map
                try:
                    name = p.split('=')[1]
                except:
                    name = None
        if name == "rules_map":
            to_pin["rules_map"] = mid
        if name == "meta_map":
            to_pin["meta_map"] = mid

    if not to_pin:
        print("No maps named 'rules_map'/'meta_map' found. Make sure you loaded the XDP program.", file=sys.stderr)
        print("You can pin maps manually with bpftool map pin MAP_ID /sys/fs/bpf/<path>", file=sys.stderr)
        return

    os.makedirs("/sys/fs/bpf", exist_ok=True)
    if "rules_map" in to_pin:
        run([BPFTOOL, "map", "pin", "id", to_pin["rules_map"], PIN_RULES])
    if "meta_map" in to_pin:
        run([BPFTOOL, "map", "pin", "id", to_pin["meta_map"], PIN_META])

def unpin_maps():
    for p in (PIN_RULES, PIN_META):
        if os.path.exists(p):
            try:
                os.unlink(p)
                print("Unpinned", p)
            except Exception as e:
                print("Failed to unpin", p, e)

def pack_rule(obj):
    # struct rule in eBPF: 9 x uint32 (little-endian on host)
    # fields: id, priority, src_ip, prefix_len, dst_port, proto, pkt_len_threshold, action, active
    id_ = int(obj.get("id", 0))
    priority = int(obj.get("priority", 1000))
    # IP address is provided as dotted string or 0
    src = obj.get("src_ip", "0.0.0.0")
    if isinstance(src, str):
        if src == "" or src == "0.0.0.0":
            src_ip = 0
        else:
            parts = src.split(".")
            if len(parts)!=4:
                raise ValueError("src_ip must be dotted IPv4")
            src_ip = (int(parts[0])<<24)|(int(parts[1])<<16)|(int(parts[2])<<8)|int(parts[3])
            # store in network order (big-endian) but we'll pack into u32 little-endian host
            # bpftool/bpf expects blob raw bytes; kernel stores value as declared. We pack as little-endian.
            # We'll pack as host-endian, kernel reads as u32. This works when both sides share endianness.
    else:
        src_ip = int(src)
    prefix_len = int(obj.get("prefix_len", 0))
    dst_port = int(obj.get("dst_port", 0))
    proto = int(obj.get("proto", 0))
    pkt_len_threshold = int(obj.get("pkt_len_threshold", 0))
    action_s = obj.get("action", "DROP").upper()
    action = 1 if action_s == "DROP" else 0
    active = 1
    packed = struct.pack("<9I", id_, priority, src_ip, prefix_len, dst_port, proto, pkt_len_threshold, action, active)
    return packed

def add_rule_from_json(path):
    with open(path, "r") as f:
        obj = json.load(f)
    if "id" not in obj:
        print("Rule JSON must include 'id' field (0..%d-1)" % (MAX_RULES))
        return
    rid = int(obj["id"])
    if rid < 0 or rid >= MAX_RULES:
        print("id out of range")
        return
    key_blob = struct.pack("<I", rid)
    val_blob = pack_rule(obj)
    with tempfile.NamedTemporaryFile(delete=False) as kf:
        kf.write(key_blob)
    with tempfile.NamedTemporaryFile(delete=False) as vf:
        vf.write(val_blob)
    run([BPFTOOL, "map", "update", "pinned", PIN_RULES, "key", kf.name, "value", vf.name])
    os.unlink(kf.name); os.unlink(vf.name)

def delete_rule(rid):
    # set active=0 for that index
    if rid < 0 or rid >= MAX_RULES: return
    # retrieve current value if any
    key_blob = struct.pack("<I", rid)
    with tempfile.NamedTemporaryFile(delete=False) as kf:
        kf.write(key_blob)
    # try to lookup
    r = run([BPFTOOL, "map", "lookup", "pinned", PIN_RULES, "key", kf.name])
    if r.returncode != 0:
        print("No rule at id", rid)
        os.unlink(kf.name)
        return
    # parse output to get value (bpftool supports --value-file? simpler: create zeroed value with active=0)
    # Build a zeroed rule with active=0
    zero_val = struct.pack("<9I", 0, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0)
    with tempfile.NamedTemporaryFile(delete=False) as vf:
        vf.write(zero_val)
    run([BPFTOOL, "map", "update", "pinned", PIN_RULES, "key", kf.name, "value", vf.name])
    os.unlink(kf.name); os.unlink(vf.name)

def list_rules():
    r = run([BPFTOOL, "map", "dump", "pinned", PIN_RULES])
    if r.returncode != 0:
        print("Failed to dump rules map. Ensure maps are pinned to", PIN_RULES)
        return
    out = r.stdout
    # parse lines like: "key: 0  value: 00 00 00 00  ..." We'll extract hex bytes after 'value:' and unpack.
    for line in out.splitlines():
        line = line.strip()
        if not line: continue
        if "key:" not in line or "value:" not in line: continue
        try:
            kpart, vpart = line.split("value:")
            key_hex = kpart.split("key:")[1].strip()
            # key_hex may be "0" or "0 0 0 0"
            # get index integer
            idx = int(key_hex.split()[0])
            # value bytes are hex pairs separated by spaces
            hexbytes = vpart.strip().split()
            b = bytes(int(x,16) for x in hexbytes)
            if len(b) < 36:
                # unexpected size
                continue
            vals = struct.unpack("<9I", b[:36])
            (rid, priority, src_ip, prefix_len, dst_port, proto, pkt_len_threshold, action, active) = vals
            if active == 0:
                continue
            src_ip_s = "{}.{}.{}.{}".format((src_ip>>24)&0xFF, (src_ip>>16)&0xFF, (src_ip>>8)&0xFF, src_ip&0xFF)
            print(f"id={rid} priority={priority} src={src_ip_s}/{prefix_len} dst_port={dst_port} proto={proto} pkt_len_threshold={pkt_len_threshold} action={'DROP' if action else 'FORWARD'}")
        except Exception as e:
            continue

def set_default_action(act):
    a = 1 if act.upper() == "DROP" else 0
    key_blob = struct.pack("<I", 0)
    val_blob = struct.pack("<I", a)  # struct meta is one uint32
    with tempfile.NamedTemporaryFile(delete=False) as kf:
        kf.write(key_blob)
    with tempfile.NamedTemporaryFile(delete=False) as vf:
        vf.write(val_blob)
    run([BPFTOOL, "map", "update", "pinned", PIN_META, "key", kf.name, "value", vf.name])
    os.unlink(kf.name); os.unlink(vf.name)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("cmd", choices=["pin-maps","unpin-maps","list","add","delete","set-default-action"])
    p.add_argument("--iface", help="interface name for pin-maps")
    p.add_argument("--json", help="rule json file")
    p.add_argument("arg", nargs="?", help="rule id or action")
    args = p.parse_args()
    if args.cmd == "pin-maps":
        if not args.iface:
            print("Please provide --iface <ifname> to pin maps based on loaded program", file=sys.stderr)
            sys.exit(1)
        pin_maps(args.iface)
    elif args.cmd == "unpin-maps":
        unpin_maps()
    elif args.cmd == "list":
        list_rules()
    elif args.cmd == "add":
        if not args.json:
            print("Provide --json rule.json", file=sys.stderr); sys.exit(1)
        add_rule_from_json(args.json)
    elif args.cmd == "delete":
        if args.arg is None:
            print("provide rule id"); sys.exit(1)
        delete_rule(int(args.arg))
    elif args.cmd == "set-default-action":
        if args.arg is None:
            print("provide FORWARD or DROP"); sys.exit(1)
        set_default_action(args.arg)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
