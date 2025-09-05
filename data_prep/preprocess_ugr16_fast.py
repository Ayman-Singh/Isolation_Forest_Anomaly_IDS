#!/usr/bin/env python3
"""
Ultra-fast UGR'16 preprocessing - optimized for speed with vectorized operations.
"""
import argparse, json, os, gc, gzip, bz2, lzma
from datetime import datetime
from typing import Dict, List, Optional
import numpy as np
import pandas as pd

# Parquet check
try: import pyarrow; PARQUET_OK = True
except: PARQUET_OK = False

# Schema mapping
COLS = {
    "timestamp": ["ts","stime","start_time","date first seen","time","start","timestamp"],
    "duration": ["td","dur","duration"], "src_ip": ["sa","src","srcaddr","srcip","source_ip","src_ip"],
    "dst_ip": ["da","dst","dstaddr","dstip","destination_ip","dst_ip"], "src_port": ["sp","sport","srcport","spt","src_port"],
    "dst_port": ["dp","dport","dstport","dpt","dst_port"], "protocol": ["pr","proto","protocol"],
    "flags": ["flg","flags","tcp_flags"], "packets": ["pkt","pkts","packets","ipkt","tot_pkts"],
    "bytes": ["byt","bytes","ibyt","tot_bytes"], "tos": ["stos","tos","type_of_service"],
    "fwd": ["fwd","forwarding status","forward_status","fwd_status"], "label": ["label","attack","is_attack","y"],
}

def find_col(df_cols, candidates): return next((c for c in df_cols if str(c).lower() in [x.lower() for x in candidates]), None)
def safe_int(s): return pd.to_numeric(s, errors="coerce").fillna(0).astype(np.int64)
def safe_float(s): return pd.to_numeric(s.astype(str).str.replace(",",".") if s.dtype==object else s, errors="coerce").fillna(0.0)

def detect_sep(sample): return max([",",";","\t","|"], key=lambda s: sample.count(s))

def read_head(path, n=64*1024):
    opener = gzip.open if path.lower().endswith(".gz") else bz2.open if path.lower().endswith(".bz2") else lzma.open if path.lower().endswith((".xz",".lzma")) else open
    try: return opener(path, "rb").read(n).decode("utf-8", errors="ignore")
    except: return ""

def parse_flags_fast(s):
    """Ultra-fast TCP flags parsing with vectorized operations"""
    out = pd.DataFrame(0, index=s.index, columns=["tcp_fin","tcp_syn","tcp_rst","tcp_psh","tcp_ack","tcp_urg","tcp_ece","tcp_cwr"], dtype=np.int8)
    if s.isna().all(): return out
    
    # Try numeric first (faster)
    num = pd.to_numeric(s, errors="coerce")
    if num.notna().mean() >= 0.9:  # numeric flags
        v = num.fillna(0).astype(int)
        for i, col in enumerate(out.columns): 
            out[col] = ((v & (1<<i)) > 0).astype(np.int8)
        return out
    
    # Optimized string processing - vectorized operations
    s_str = s.fillna("").astype(str)
    # Direct character checks instead of regex (much faster)
    out["tcp_fin"] = s_str.str.contains('F', case=False, na=False).astype(np.int8)
    out["tcp_syn"] = s_str.str.contains('S', case=False, na=False).astype(np.int8)  
    out["tcp_rst"] = s_str.str.contains('R', case=False, na=False).astype(np.int8)
    out["tcp_psh"] = s_str.str.contains('P', case=False, na=False).astype(np.int8)
    out["tcp_ack"] = s_str.str.contains('A', case=False, na=False).astype(np.int8)
    out["tcp_urg"] = s_str.str.contains('U', case=False, na=False).astype(np.int8)
    out["tcp_ece"] = s_str.str.contains('E', case=False, na=False).astype(np.int8)
    out["tcp_cwr"] = s_str.str.contains('C', case=False, na=False).astype(np.int8)
    return out

def parse_proto_fast(s):
    """Ultra-fast protocol parsing"""
    out = pd.DataFrame(0, index=s.index, columns=["pr_tcp","pr_udp","pr_icmp","pr_other"], dtype=np.int8)
    
    # Try numeric first (fastest)
    if s.dtype != object:
        v = safe_int(s)
        out["pr_tcp"] = (v == 6).astype(np.int8)
        out["pr_udp"] = (v == 17).astype(np.int8) 
        out["pr_icmp"] = (v == 1).astype(np.int8)
    else:
        # Optimized string matching
        s_str = s.fillna("").astype(str).str.upper()
        out["pr_tcp"] = s_str.str.contains("TCP", na=False).astype(np.int8)
        out["pr_udp"] = s_str.str.contains("UDP", na=False).astype(np.int8)
        out["pr_icmp"] = s_str.str.contains("ICMP", na=False).astype(np.int8)
    
    out["pr_other"] = (~out[["pr_tcp","pr_udp","pr_icmp"]].any(axis=1)).astype(np.int8)
    return out

def port_features_fast(s, prefix):
    """Optimized port feature extraction"""
    v = safe_int(s).clip(0, 65535)
    # Vectorized comparisons
    low_mask = v < 1024
    mid_mask = (v >= 1024) & (v <= 49151)
    high_mask = v > 49151
    
    return pd.DataFrame({
        f"{prefix}_port": v,
        f"{prefix}_port_low": low_mask.astype(np.int8),
        f"{prefix}_port_mid": mid_mask.astype(np.int8),
        f"{prefix}_port_high": high_mask.astype(np.int8)
    }, index=s.index)

def derive_features_fast(df, mapping):
    """Ultra-fast feature derivation with optimized operations"""
    # Base features - vectorized
    dur = safe_float(df[mapping["duration"]]) if mapping["duration"] else pd.Series(0.0, index=df.index)
    pkt = safe_float(df[mapping["packets"]]) if mapping["packets"] else pd.Series(0.0, index=df.index)
    byt = safe_float(df[mapping["bytes"]]) if mapping["bytes"] else pd.Series(0.0, index=df.index)
    
    # Create base DataFrame
    out = pd.DataFrame({
        "duration": dur.clip(0),
        "packets": pkt.clip(0), 
        "bytes": byt.clip(0)
    }, index=df.index)
    
    # Vectorized ratio calculations with safe division
    pkt_safe = pkt.where(pkt > 0, 1e-9)
    dur_safe = dur.where(dur > 0, 1e-6)
    
    out["bytes_per_packet"] = byt / pkt_safe
    out["packets_per_sec"] = pkt / dur_safe  
    out["bytes_per_sec"] = byt / dur_safe
    
    # Protocol features
    if mapping["protocol"]:
        proto_df = parse_proto_fast(df[mapping["protocol"]])
    else:
        proto_df = pd.DataFrame({"pr_tcp":0,"pr_udp":0,"pr_icmp":0,"pr_other":1}, index=df.index)
    out = pd.concat([out, proto_df], axis=1)
    
    # TCP flags 
    if mapping["flags"]:
        flags_df = parse_flags_fast(df[mapping["flags"]])
    else:
        flags_df = pd.DataFrame({k:0 for k in ["tcp_fin","tcp_syn","tcp_rst","tcp_psh","tcp_ack","tcp_urg","tcp_ece","tcp_cwr"]}, index=df.index)
    out = pd.concat([out, flags_df], axis=1)
    
    # Port features
    for key, prefix in [("src_port", "src"), ("dst_port", "dst")]:
        if mapping[key]:
            port_df = port_features_fast(df[mapping[key]], prefix)
        else:
            port_df = pd.DataFrame({f"{prefix}_port":0,f"{prefix}_port_low":0,f"{prefix}_port_mid":0,f"{prefix}_port_high":0}, index=df.index)
        out = pd.concat([out, port_df], axis=1)
    
    # Simple numeric features
    out["tos"] = safe_int(df[mapping["tos"]]).clip(0) if mapping["tos"] else 0
    out["fwd"] = safe_int(df[mapping["fwd"]]).clip(0) if mapping["fwd"] else 0
    
    # Vectorized log features - use numpy for speed
    log_cols = ["bytes", "packets", "bytes_per_packet", "packets_per_sec", "bytes_per_sec"]
    for col in log_cols:
        out[f"log1p_{col}"] = np.log1p(out[col].values)
    
    # Optimized time features
    if mapping["timestamp"]:
        ts = pd.to_datetime(df[mapping["timestamp"]], format="%Y-%m-%d %H:%M:%S", errors="coerce")
        if ts.isna().mean() > 0.2:
            ts = pd.to_datetime(df[mapping["timestamp"]], errors="coerce")
        
        if not ts.isna().all():
            h, d = ts.dt.hour.fillna(0).values, ts.dt.dayofweek.fillna(0).values
            # Vectorized trigonometric operations
            out["hour_sin"] = np.sin(2*np.pi*h/24)
            out["hour_cos"] = np.cos(2*np.pi*h/24) 
            out["dow_sin"] = np.sin(2*np.pi*d/7)
            out["dow_cos"] = np.cos(2*np.pi*d/7)
        else:
            out["hour_sin"] = out["hour_cos"] = out["dow_sin"] = out["dow_cos"] = 0.0
    else:
        out["hour_sin"] = out["hour_cos"] = out["dow_sin"] = out["dow_cos"] = 0.0
    
    return out

def detect_label(df, mapping):
    if mapping["label"]:
        s = df[mapping["label"]]
        if s.dtype == object: return s.astype(str).str.lower().isin(["1","true","attack","anomaly","malicious","dos","scan","botnet"]).astype(np.int8)
        return (safe_int(s) > 0).astype(np.int8)
    # Multi-label aggregation for UGR16
    attack_cols = [c for c in df.columns if isinstance(c, str) and (c.lower().startswith("label") or c.lower().startswith("attack")) and all(x not in c.lower() for x in ("blacklist","normal","background"))]
    if attack_cols: return (df[attack_cols].apply(pd.to_numeric, errors="coerce").fillna(0).sum(axis=1) > 0).astype(np.int8)
    return pd.Series(0, index=df.index, dtype=np.int8)

def open_reader_fast(path, chunksize, force_sep):
    """Optimized CSV reader with better engine selection"""
    sample = read_head(path)
    sep = force_sep or detect_sep(sample)
    
    # Use faster C engine when possible
    engine = "c" if sep in [",", "\t"] else "python"
    
    try: 
        probe = pd.read_csv(path, nrows=5, sep=sep, compression="infer", on_bad_lines="skip", engine=engine)
    except Exception as e: 
        raise ValueError(f"Cannot read {path}: {e}")
    
    # Check if headerless (UGR16 common case)
    cols_lower = [str(c).lower() for c in probe.columns]
    has_header = any(any(k in col for k in ["time","dur","pkt","byt","proto","flag"]) for col in cols_lower)
    
    if not has_header:
        n = len(probe.columns)
        names = ["timestamp","duration","src_ip","dst_ip","src_port","dst_port","protocol","flags","fwd_status","tos","packets","bytes","label"][:n] if n >= 12 else ["timestamp","duration","src_ip","dst_ip","src_port","dst_port","protocol","flags","fwd_status","tos","packets","bytes"][:n]
        return pd.read_csv(path, chunksize=chunksize, sep=sep, compression="infer", on_bad_lines="skip", engine=engine, header=None, names=names, dtype=str), sep
    return pd.read_csv(path, chunksize=chunksize, sep=sep, compression="infer", on_bad_lines="skip", engine=engine, dtype=str), sep

def downcast_numeric_fast(df: pd.DataFrame) -> pd.DataFrame:
    """Optimized memory reduction"""
    # Vectorized downcasting
    float_cols = df.select_dtypes(include=["float64"]).columns
    if len(float_cols):
        df[float_cols] = df[float_cols].astype(np.float32)
    
    int_cols = df.select_dtypes(include=["int64"]).columns
    for c in int_cols:
        df[c] = pd.to_numeric(df[c], downcast="integer")
    return df

def write_data(df, path, fmt, part_idx):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if fmt == "csv": 
        df.to_csv(path, index=False, header=not os.path.exists(path), mode="a")
    else:
        part_dir = path.replace(".parquet", "_parts")
        os.makedirs(part_dir, exist_ok=True)
        try: 
            if not PARQUET_OK: raise ImportError()
            # Use faster compression
            df.to_parquet(f"{part_dir}/part-{part_idx:06d}.parquet", index=False, compression="snappy")  # snappy is faster than zstd
        except: 
            df.to_csv(path.replace(".parquet", ".csv"), index=False, header=not os.path.exists(path.replace(".parquet", ".csv")), mode="a")

def _next_parquet_part_idx(path):
    """Return next part index for a parquet dataset path (resume-safe)."""
    import re
    part_dir = path.replace(".parquet", "_parts")
    if not os.path.isdir(part_dir):
        return 0
    max_idx = -1
    try:
        for name in os.listdir(part_dir):
            m = re.match(r"part-(\d+)\.parquet$", name)
            if m:
                i = int(m.group(1))
                if i > max_idx:
                    max_idx = i
    except Exception:
        return 0
    return max_idx + 1 if max_idx >= 0 else 0

def load_checkpoint(output_dir): 
    cp = os.path.join(output_dir, ".checkpoint.json")
    try: return json.load(open(cp)) if os.path.exists(cp) else {}
    except: return {}

def save_checkpoint(output_dir, data): 
    with open(os.path.join(output_dir, ".checkpoint.json"), "w") as f: json.dump(data, f)

def get_month_from_path(path):
    """Extract month from file path or filename"""
    path_lower = path.lower()
    if "march" in path_lower or "/03" in path_lower or "_03" in path_lower: return "march"
    if "april" in path_lower or "/04" in path_lower or "_04" in path_lower: return "april" 
    if "may" in path_lower or "/05" in path_lower or "_05" in path_lower: return "may"
    if "june" in path_lower or "/06" in path_lower or "_06" in path_lower: return "june"
    if "july" in path_lower or "/07" in path_lower or "_07" in path_lower: return "july"
    if "august" in path_lower or "/08" in path_lower or "_08" in path_lower: return "august"
    return "unknown"

def expand_files(paths):
    files = []
    for p in paths:
        if os.path.isdir(p): files.extend([os.path.join(r,f) for r,_,fs in os.walk(p) for f in fs if os.path.getsize(os.path.join(r,f)) > 0])
        elif os.path.isfile(p) and os.path.getsize(p) > 0: files.append(p)
    return sorted(files) or (_ for _ in ()).throw(FileNotFoundError("No files found"))

def main():
    p = argparse.ArgumentParser(description="Ultra-fast UGR'16 preprocessor")
    p.add_argument("--input", nargs="+", required=True, help="Input files/dirs")
    p.add_argument("--output-dir", required=True, help="Output directory")
    p.add_argument("--chunksize", type=int, default=1000000)  # Larger default for speed
    p.add_argument("--format", choices=["csv","parquet"], default="csv")
    p.add_argument("--max-rows", type=int, help="Row limit for testing")
    p.add_argument("--force-sep", choices=[",",";","\t","|"])
    p.add_argument("--resume", action="store_true")
    p.add_argument("--overwrite", action="store_true")
    args = p.parse_args()
    
    # Always train only on normal traffic with temporal split
    normal_only_train = True
    
    if args.format == "parquet" and not PARQUET_OK: print("Warning: pyarrow missing, falling back to CSV")
    
    files = expand_files(args.input)
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Categorize files by month for temporal split
    train_months = ["march", "april", "may", "june"]
    test_months = ["july", "august"]
    train_files = [f for f in files if get_month_from_path(f) in train_months]
    test_files = [f for f in files if get_month_from_path(f) in test_months]
    print(f"Temporal split: {len(train_files)} train files (Mar-Jun), {len(test_files)} test files (Jul-Aug)")
    
    checkpoint = {} if args.overwrite else load_checkpoint(args.output_dir) if args.resume else {}
    train_path = os.path.join(args.output_dir, f"train.{args.format}")
    test_path = os.path.join(args.output_dir, f"test.{args.format}")
    
    if args.overwrite or not args.resume:
        for p in [train_path, test_path]: 
            if args.format == "csv" and os.path.exists(p): os.remove(p)
    
    features, total_rows, train_rows, test_rows, part_idx = None, 0, 0, 0, 0
    
    print(f"Processing {len(files)} files (resume: {args.resume}, processed: {len(checkpoint)})")
    
    # Initialize part index for parquet resume (scan existing parts)
    if args.format == "parquet":
        part_idx = max(_next_parquet_part_idx(train_path), _next_parquet_part_idx(test_path))

    def handle_files_fast(file_list, out_path, write_all):
        nonlocal features, total_rows, train_rows, test_rows, part_idx
        if not file_list: return
        print(("Processing training data (March-June)..." if not write_all else "Processing testing data (July-August)..."))
        
        for fpath in file_list:
            if args.resume and fpath in checkpoint: continue
            try:
                reader, _ = open_reader_fast(fpath, args.chunksize, args.force_sep)
            except Exception as e:
                print(f"Skip {fpath}: {e}"); continue
                
            for chunk_idx, chunk in enumerate(reader, 1):
                try:
                    # Fast column mapping
                    mapping = {k: find_col(chunk.columns, v) for k, v in COLS.items()}
                    
                    # Fast feature derivation
                    derived = derive_features_fast(chunk, mapping)
                    derived["label"] = detect_label(chunk, mapping)
                    
                    # Fast cleanup
                    num_cols = derived.select_dtypes(include=[np.number]).columns
                    derived = derived.dropna(subset=num_cols, how="all")
                    derived[num_cols] = derived[num_cols].fillna(0)
                    
                    # Feature consistency
                    if features is None:
                        features = [c for c in derived.columns if c != "label"]
                        json.dump(features, open(os.path.join(args.output_dir, "features.json"), "w"), indent=2)
                    
                    for f in features + ["label"]:
                        if f not in derived.columns: derived[f] = 0
                    derived = derived[features + ["label"]]
                    
                    # Filter and optimize
                    df = derived if write_all else derived[derived["label"] == 0]
                    if len(df):
                        df = downcast_numeric_fast(df)
                        write_data(df, out_path, args.format, part_idx)
                        if write_all: test_rows += len(df)
                        else: train_rows += len(df)
                        part_idx += 1
                    
                    total_rows += len(derived)
                    
                    # Aggressive memory cleanup
                    del chunk, derived
                    if 'df' in locals() and df is not None: del df
                    gc.collect()
                    
                    # Progress reporting
                    if chunk_idx % 10 == 0:  # More frequent progress updates
                        print(f"{os.path.basename(fpath)}: {chunk_idx} chunks, {total_rows} rows processed")
                    
                    if args.max_rows and total_rows >= args.max_rows: break
                except Exception as e:
                    print(f"Error chunk {chunk_idx}: {e}"); continue
            
            checkpoint[fpath] = datetime.now().isoformat()
            save_checkpoint(args.output_dir, checkpoint)
            if args.max_rows and total_rows >= args.max_rows: break

    # Process files
    handle_files_fast(train_files, train_path, write_all=False)
    handle_files_fast(test_files, test_path, write_all=True)
    
    if not features: raise RuntimeError("No data processed")
    
    # Save metadata
    actual_format = "parquet" if (args.format == "parquet" and PARQUET_OK) else "csv"
    meta = {
        "generated": datetime.now().isoformat(), 
        "files": len(files), 
        "train_files": len(train_files),
        "test_files": len(test_files),
        "total_rows": total_rows, 
        "train_rows": train_rows, 
        "test_rows": test_rows, 
        "features": features,
        "num_features": len(features),
        "dataset": "UGR16",
        "format": args.format,
        "actual_format": actual_format,
        "temporal_split": True,
        "train_months": "March-June",
        "test_months": "July-August",
        "normal_only_train": True
    }
    json.dump(meta, open(os.path.join(args.output_dir, "meta.json"), "w"), indent=2)
    
    print(f"Done: {train_rows} train, {test_rows} test rows")
    print("Temporal split: Training on Mar-Jun, Testing on Jul-Aug")
    if train_rows == 0: print("WARNING: No training data!")

if __name__ == "__main__": main()
