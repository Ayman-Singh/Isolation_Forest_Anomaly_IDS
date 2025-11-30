#!/usr/bin/env python3
import argparse
import json
import math
import os
import sys
import subprocess
import numpy as np
import pandas as pd
from joblib import load
from collections import OrderedDict
from model_script import IDS
# Anomaly threshold for decision_function
THR = -0.093570

# 22 features in exact order required by model
FEATS = [
    "duration", "packets", "bytes", "bps", "pps", 
    "log_bytes", "log_packets", "tcp", "udp", "icmp",
    "fin", "syn", "rst", "psh", "ack", "urg",
    "src_port", "src_low", "src_high", 
    "dst_port", "dst_low", "dst_high"
]

PROTO_MAP = {6: 'tcp', 17: 'udp', 1: 'icmp'}

def derive_features_from_log(log_entry):
    """Derive 22 ML features from log entry. Hardcoded: duration=0.001, packets=1, bytes=64"""
    src_port = int(log_entry.get('src_port', 0) or 0)
    dst_port = int(log_entry.get('dst_port', 0) or 0)
    proto = int(log_entry.get('proto', 0) or 0)
    tcp_flags = int(log_entry.get('tcp_flags', 0) or 0)
    
    duration = 0.001  # 1ms (single packet)
    packets = 1
    bytes_val = 64    # avg packet size
    
    bps = bytes_val / max(packets, 1)
    pps = packets / max(duration, 1e-3)
    log_bytes = math.log1p(bytes_val)
    log_packets = math.log1p(packets)
    
    tcp = int(proto == 6)
    udp = int(proto == 17)
    icmp = int(proto == 1)
    
    if tcp:
        fin = int(tcp_flags & 0x01 > 0)
        syn = int(tcp_flags & 0x02 > 0)
        rst = int(tcp_flags & 0x04 > 0)
        psh = int(tcp_flags & 0x08 > 0)
        ack = int(tcp_flags & 0x10 > 0)
        urg = int(tcp_flags & 0x20 > 0)
    else:
        fin = syn = rst = psh = ack = urg = 0
    
    src_low = int(src_port < 1024)
    src_high = int(src_port > 49151)
    dst_low = int(dst_port < 1024)
    dst_high = int(dst_port > 49151)
    
    return [
        duration, packets, bytes_val, bps, pps,
        log_bytes, log_packets, tcp, udp, icmp,
        fin, syn, rst, psh, ack, urg,
        src_port, src_low, src_high,
        dst_port, dst_low, dst_high
    ]

def load_obj(path):
    """Load ML model from joblib file."""
    o = load(path)
    if isinstance(o, dict):
        m = o.get("model") or o.get("estimator") or o.get("ids") or o.get("clf") or o.get("pipeline")
        s = o.get("scaler") or o.get("preprocessor") or None
        feats = o.get("features") or o.get("feature_list") or None
        if m is None:
            m = o
    else:
        m = o
        s = getattr(o, "scaler", None)
        feats = getattr(o, "features", None)
    return m, s, feats

def predict(m, s, X):
    """Predict anomaly: returns (score, label) where label 0=normal/PASS, 1=anomaly/DROP"""
    Xp = X
    internal_scaler = getattr(m, "scaler", None) is not None
    if s is not None and not internal_scaler:
        Xp = s.transform(Xp)
    
    if hasattr(m, "decision_function"):
        sc = m.decision_function(Xp)[0]
    elif hasattr(m, "score_samples"):
        sc = m.score_samples(Xp)[0]
    else:
        pred = m.predict(Xp)[0]
        return 0.0, (1 if pred == -1 else 0)
    
    return float(sc), int(sc < THR)

def normalize_entry(obj):
    """Extract 5-tuple key and fields from log entry"""
    src_ip = obj.get('src_ip', '0.0.0.0')
    dst_ip = obj.get('dst_ip', '0.0.0.0')
    src_port = int(obj.get('src_port', 0) or 0)
    dst_port = int(obj.get('dst_port', 0) or 0)
    proto = int(obj.get('proto', 0) or 0)
    
    proto_str = PROTO_MAP.get(proto, str(proto))
    
    key = (src_ip, dst_ip, src_port, dst_port, proto)
    fields = {
        'src': src_ip,
        'dst': dst_ip,
        'sport': str(src_port),
        'dport': str(dst_port),
        'proto': proto_str,
    }
    return key, fields

def build_manager_cmd(manager_path, fields, action):
    """Build manager command to add firewall rule (action='pass' or 'drop')"""
    cmd = [manager_path, 'add']
    cmd += ['--src', fields['src']]
    cmd += ['--dst', fields['dst']]
    
    proto = fields.get('proto', '')
    if proto in ('tcp', 'udp'):
        if fields.get('sport', '0') != '0':
            cmd += ['--sport', fields['sport']]
        if fields.get('dport', '0') != '0':
            cmd += ['--dport', fields['dport']]
    
    cmd += ['--proto', proto]
    cmd += ['--action', action]
    return cmd

def main():
    parser = argparse.ArgumentParser(description='ML-based firewall: reads logs, predicts, adds rules')
    parser.add_argument('--file', '-f', default='firewall_log.json', help='JSON log file')
    parser.add_argument('--model', default='ugr16_if_stream_ms16384_20251003_181922.joblib', help='ML model')
    parser.add_argument('--manager', '-m', default='./manager', help='Manager executable')
    parser.add_argument('--out-file', '-o', default='ml_firewall_commands.json', help='Output JSON')
    parser.add_argument('--apply', action='store_true', help='Execute commands immediately')
    parser.add_argument('--no-sudo', action='store_true', help='No sudo prefix')
    
    args = parser.parse_args()
    
    if not os.path.isfile(args.file):
        print(f"Error: log file not found: {args.file}")
        sys.exit(2)
    
    if not os.path.isfile(args.model):
        print(f"Error: model file not found: {args.model}")
        sys.exit(2)
    
    print(f"Loading ML model from {args.model}...")
    try:
        model, scaler, feature_names = load_obj(args.model)
        print(f"✓ Model loaded successfully")
    except Exception as e:
        print(f"Error loading model: {e}")
        sys.exit(3)
    
    print(f"Reading log entries from {args.file}...")
    
    # First pass: Aggregate flows
    flows = {}
    
    with open(args.file, 'r') as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Skipping line {lineno}: JSON decode error: {e}")
                continue
            
            key, fields = normalize_entry(obj)
            
            if key not in flows:
                flows[key] = {
                    'fields': fields,
                    'packets': 0,
                    'bytes': 0,
                    'start_ts': float('inf'),
                    'end_ts': 0,
                    'tcp_flags': 0,
                    'proto': obj.get('proto', 0),
                    'src_port': obj.get('src_port', 0),
                    'dst_port': obj.get('dst_port', 0)
                }
            
            f = flows[key]
            f['packets'] += 1
            f['bytes'] += obj.get('len', 64) # Default to 64 if missing
            ts = obj.get('timestamp', 0)
            if ts > 0:
                if ts < f['start_ts']: f['start_ts'] = ts
                if ts > f['end_ts']: f['end_ts'] = ts
            f['tcp_flags'] |= obj.get('tcp_flags', 0)

    if not flows:
        print("No entries found in the log file.")
        return
    
    print(f"Found {len(flows)} unique flow(s) to analyze")
    
    commands = []
    stats = {'normal': 0, 'anomaly': 0}
    
    for i, (key, flow) in enumerate(flows.items(), start=1):
        # Calculate derived features
        duration_ns = flow['end_ts'] - flow['start_ts']
        if duration_ns < 0: duration_ns = 0
        duration = duration_ns / 1e9 # Convert to seconds
        if duration == 0: duration = 0.001 # Avoid div by zero
        
        packets = flow['packets']
        bytes_val = flow['bytes']
        bps = bytes_val / duration
        pps = packets / duration
        
        log_bytes = math.log1p(bytes_val)
        log_packets = math.log1p(packets)
        
        # Prepare feature vector
        proto = flow['proto']
        tcp_flags = flow['tcp_flags']
        src_port = flow['src_port']
        dst_port = flow['dst_port']
        
        tcp = int(proto == 6)
        udp = int(proto == 17)
        icmp = int(proto == 1)
        
        if tcp:
            fin = int(tcp_flags & 0x01 > 0)
            syn = int(tcp_flags & 0x02 > 0)
            rst = int(tcp_flags & 0x04 > 0)
            psh = int(tcp_flags & 0x08 > 0)
            ack = int(tcp_flags & 0x10 > 0)
            urg = int(tcp_flags & 0x20 > 0)
        else:
            fin = syn = rst = psh = ack = urg = 0
        
        src_low = int(src_port < 1024)
        src_high = int(src_port > 49151)
        dst_low = int(dst_port < 1024)
        dst_high = int(dst_port > 49151)
        
        features = [
            duration, packets, bytes_val, bps, pps,
            log_bytes, log_packets, tcp, udp, icmp,
            fin, syn, rst, psh, ack, urg,
            src_port, src_low, src_high,
            dst_port, dst_low, dst_high
        ]

        df = pd.DataFrame([features], columns=FEATS).astype(np.float32)
        
        try:
            score, label = predict(model, scaler, df.values)
            action = 'drop' if label == 1 else 'pass'
            decision = 'ANOMALY' if label == 1 else 'NORMAL'
            stats[decision.lower()] += 1
            
            fields = flow['fields']
            print(f"[{i}/{len(flows)}] {fields['src']}:{fields['sport']} → {fields['dst']}:{fields['dport']} "
                  f"({fields['proto']}) | Pkts: {packets}, Bytes: {bytes_val}, Dur: {duration:.4f}s | Score: {score:.4f} | {decision} → {action.upper()}")
            
        except Exception as e:
            print(f"[{i}/{len(flows)}] Error predicting: {e}")
            action = 'pass'  # fail-open on error
            score = 0.0
            label = 0
            stats['normal'] += 1
        
        cmd = build_manager_cmd(args.manager, fields, action)
        cmd_with_sudo = list(cmd) if args.no_sudo else ['sudo'] + cmd
        
        entry = {
            'cmd': cmd_with_sudo,
            'fields': fields,
            'features': {
                'duration': duration, 'packets': packets, 'bytes': bytes_val,
                'bps': bps, 'pps': pps
            },
            'ml_score': float(score),
            'ml_label': int(label),
            'action': action
        }
        commands.append(entry)
        
        if args.apply:
            try:
                print(f"  → Executing: {' '.join(cmd_with_sudo)}")
                proc = subprocess.run(cmd_with_sudo, stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, text=True)
                rc = proc.returncode
                stdout = proc.stdout.strip()
                stderr = proc.stderr.strip()
                
                applied = 'rule added' in stdout.lower() or 'rule added' in stderr.lower()
                entry['result'] = {'rc': rc, 'stdout': stdout, 'stderr': stderr, 'applied': applied}
                
                if rc != 0:
                    print(f"  → Command exited {rc}. stderr: {stderr}")
                elif applied:
                    print(f"  → ✓ Rule added successfully")
                else:
                    print(f"  → Completed (no 'rule added'). stdout: {stdout}")
                    
            except FileNotFoundError:
                entry['result'] = {'rc': None, 'stdout': '', 
                                   'stderr': f'executable not found: {cmd_with_sudo[0]}', 'applied': False}
                print(f"  → Failed: executable not found: {cmd_with_sudo[0]}")
            except Exception as e:
                entry['result'] = {'rc': None, 'stdout': '', 'stderr': str(e), 'applied': False}
                print(f"  → Failed: {e}")
    
    try:
        with open(args.out_file, 'w') as out_fh:
            json.dump(commands, out_fh, indent=2)
        print(f"\n✓ Wrote {len(commands)} commands to {args.out_file}")
    except Exception as e:
        print(f"Failed to write output file {args.out_file}: {e}")
        sys.exit(4)
    
    print(f"\n{'='*60}")
    print(f"ML Prediction Summary:")
    print(f"  Normal traffic (PASS):  {stats['normal']}")
    print(f"  Anomalies (DROP):       {stats['anomaly']}")
    print(f"  Total flows analyzed:   {len(flows)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    if len(sys.argv) == 1:  # Test mode
        print("TEST MODE: Testing feature derivation and model prediction\n")
        
        sample_log = {
            'src_ip': '127.0.0.1', 'dst_ip': '127.0.0.1',
            'src_port': 52314, 'dst_port': 80,
            'proto': 6, 'tcp_flags': 0x12  # SYN+ACK
        }
        
        features = derive_features_from_log(sample_log)
        print(f"Derived features (22): {features}")
        
        df = pd.DataFrame([features], columns=FEATS).astype(np.float32)
        print(f"\nFeature DataFrame:\n{df}\n")
        
        model_path = "ugr16_if_stream_ms16384_20251003_181922.joblib"
        if os.path.isfile(model_path):
            m, s, feats = load_obj(model_path)
            score, label = predict(m, s, df.values)
            decision = "ANOMALY (DROP)" if label == 1 else "NORMAL (PASS)"
            print(f"ML Prediction: score={score:.4f}, label={label} → {decision}")
        else:
            print(f"Model file not found: {model_path}")
        
        print("\n" + "="*60)
        print("Usage: python3 model_loader.py --file firewall_log.json --apply")
        print("="*60)
    else:
        main()
