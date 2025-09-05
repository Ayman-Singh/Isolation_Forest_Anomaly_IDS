import pandas as pd
import numpy as np
from datetime import datetime
import gc
import os
import logging
import joblib
import json
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (
    precision_recall_fscore_support,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)
from typing import Optional, Tuple
import warnings

warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

COLS = {
    "timestamp": ["ts","stime","start_time","date first seen","time","start","timestamp"],
    "duration": ["td","dur","duration"], 
    "src_ip": ["sa","src","srcaddr","srcip","source_ip","src_ip"],
    "dst_ip": ["da","dst","dstaddr","dstip","destination_ip","dst_ip"], 
    "src_port": ["sp","sport","srcport","spt","src_port"],
    "dst_port": ["dp","dport","dstport","dpt","dst_port"], 
    "protocol": ["pr","proto","protocol"],
    "flags": ["flg","flags","tcp_flags"], 
    "packets": ["pkt","pkts","packets","ipkt","tot_pkts"],
    "bytes": ["byt","bytes","ibyt","tot_bytes"], 
    "tos": ["stos","tos","type_of_service"],
    "fwd": ["fwd","forwarding status","forward_status","fwd_status"], 
    "label": ["label","attack","is_attack","y"],
}

def find_col(df_cols, candidates): 
    return next((c for c in df_cols if str(c).lower() in [x.lower() for x in candidates]), None)

def safe_numeric(s, dtype=np.float32): 
    return pd.to_numeric(s, errors="coerce").fillna(0).astype(dtype)

def detect_sep(sample): 
    return max([",",";","\t","|"], key=lambda s: sample.count(s))

def parse_flags(s):
    out = pd.DataFrame(0, index=s.index, columns=["fin","syn","rst","psh","ack","urg"], dtype=np.int8)
    if s.isna().all(): return out
    
    num = pd.to_numeric(s, errors="coerce")
    if num.notna().mean() >= 0.8:
        v = num.fillna(0).astype(int)
        for i, col in enumerate(out.columns): 
            out[col] = ((v & (1<<i)) > 0).astype(np.int8)
    else:
        s_clean = s.fillna("").astype(str).str.upper()
        for col, letter in zip(out.columns, ["F","S","R","P","A","U"]): 
            out[col] = s_clean.str.contains(letter, na=False).astype(np.int8)
    return out

def parse_proto(s):
    out = pd.DataFrame(0, index=s.index, columns=["tcp","udp","icmp"], dtype=np.int8)
    if s.dtype == object:
        s_up = s.fillna("").astype(str).str.upper()
        out["tcp"] = s_up.str.contains("TCP", na=False).astype(np.int8)
        out["udp"] = s_up.str.contains("UDP", na=False).astype(np.int8)
        out["icmp"] = s_up.str.contains("ICMP", na=False).astype(np.int8)
    else:
        v = safe_numeric(s, np.int32)
        out["tcp"] = (v == 6).astype(np.int8)
        out["udp"] = (v == 17).astype(np.int8)
        out["icmp"] = (v == 1).astype(np.int8)
    return out

def port_features(s, prefix):
    v = safe_numeric(s, np.int32).clip(0, 65535)
    return pd.DataFrame({
        f"{prefix}_port": v, 
        f"{prefix}_low": (v < 1024).astype(np.int8),
        f"{prefix}_high": (v > 49151).astype(np.int8)
    }, index=s.index)

def derive_features(df, mapping):
    dur = safe_numeric(df[mapping["duration"]]) if mapping["duration"] else pd.Series(0.0, index=df.index)
    pkt = safe_numeric(df[mapping["packets"]]) if mapping["packets"] else pd.Series(0.0, index=df.index)
    byt = safe_numeric(df[mapping["bytes"]]) if mapping["bytes"] else pd.Series(0.0, index=df.index)
    
    out = pd.DataFrame({
        "duration": dur.clip(0), 
        "packets": pkt.clip(0), 
        "bytes": byt.clip(0),
        "bps": byt / pkt.where(pkt > 0, 1),
        "pps": pkt / np.maximum(dur, 1e-3),
        "log_bytes": np.log1p(byt),
        "log_packets": np.log1p(pkt)
    }, index=df.index)
    
    out = pd.concat([out, parse_proto(df[mapping["protocol"]]) if mapping["protocol"] else 
                    pd.DataFrame({"tcp":0,"udp":0,"icmp":0}, index=df.index)], axis=1)
    out = pd.concat([out, parse_flags(df[mapping["flags"]]) if mapping["flags"] else 
                    pd.DataFrame({f:0 for f in ["fin","syn","rst","psh","ack","urg"]}, index=df.index)], axis=1)
    
    for key, prefix in [("src_port", "src"), ("dst_port", "dst")]:
        out = pd.concat([out, port_features(df[mapping[key]], prefix) if mapping[key] else 
                        pd.DataFrame({f"{prefix}_port":0,f"{prefix}_low":0,f"{prefix}_high":0}, index=df.index)], axis=1)
    
    return out.astype(np.float32)

def detect_label(df, mapping):
    if mapping["label"]:
        s = df[mapping["label"]]
        if s.dtype == object: 
            s_lower = s.astype(str).str.lower()
            return (~s_lower.isin(["background", "normal", "benign"])).astype(np.int8)
        return (safe_numeric(s, np.int32) > 0).astype(np.int8)
    
    last_col = df.iloc[:, -1] if len(df.columns) > 0 else pd.Series(dtype=object)
    if last_col.dtype == object:
        s_lower = last_col.astype(str).str.lower()
        return (~s_lower.isin(["background", "normal", "benign"])).astype(np.int8)
    
    return pd.Series(0, index=df.index, dtype=np.int8)

def get_month(path):
    path_lower = path.lower()
    if "march" in path_lower: return "march"
    if "april" in path_lower: return "april" 
    if "may" in path_lower: return "may"
    if "june" in path_lower: return "june"
    if "july" in path_lower: return "july"
    if "august" in path_lower: return "august"
    return "unknown"

def expand_files(paths):
    files = []
    for p in paths:
        if os.path.isdir(p): 
            files.extend([os.path.join(r,f) for r,_,fs in os.walk(p) for f in fs if os.path.getsize(os.path.join(r,f)) > 0])
        elif os.path.isfile(p) and os.path.getsize(p) > 0: 
            files.append(p)
    return sorted(files)

def preprocess_data(input_paths, output_dir, chunksize=100000, max_rows=None):
    logger.info("Starting preprocessing...")
    
    files = expand_files(input_paths)
    os.makedirs(output_dir, exist_ok=True)
    
    train_months = ["march"]
    test_months = ["april", "may", "june", "july", "august"]
    train_files = [f for f in files if get_month(f) in train_months]
    # Only include test months if any provided input path mentions them; prevents accidental April processing
    inputs_lower = " ".join(input_paths).lower() if isinstance(input_paths, list) else str(input_paths).lower()
    enable_test = any(m in inputs_lower for m in test_months)
    test_files = [f for f in files if get_month(f) in test_months] if enable_test else []
    
    train_path = os.path.join(output_dir, "train.csv")
    test_path = os.path.join(output_dir, "test.csv")
    
    for p in [train_path, test_path]: 
        if os.path.exists(p): os.remove(p)
    
    features, total_rows, train_rows, test_rows = None, 0, 0, 0
    
    def process_files(file_list, out_path, keep_attacks):
        nonlocal features, total_rows, train_rows, test_rows
        if not file_list: return
        
        for fpath in file_list:
            try:
                sep = detect_sep(open(fpath, 'rb').read(8192).decode('utf-8', errors='ignore'))
                
                # UGR16 files are headerless - define standard column names
                ugr16_cols = ["timestamp","duration","src_ip","dst_ip","src_port","dst_port","protocol","flags","tos","fwd","packets","bytes","label"]
                reader = pd.read_csv(fpath, chunksize=chunksize, sep=sep, on_bad_lines="skip", header=None, names=ugr16_cols)

                for i, chunk in enumerate(reader, 1):
                    mapping = {k: find_col(chunk.columns, v) for k, v in COLS.items()}
                    derived = derive_features(chunk, mapping)
                    derived["label"] = detect_label(chunk, mapping)
                    derived = derived.fillna(0).dropna(how='all')
                    
                    if features is None:
                        features = [c for c in derived.columns if c != "label"]
                        with open(os.path.join(output_dir, "features.json"), "w") as f:
                            json.dump(features, f)
                    
                    df = derived if keep_attacks else derived[derived["label"] == 0]
                    
                    if len(df):
                        df.to_csv(out_path, index=False, header=not os.path.exists(out_path), mode="a")
                        if keep_attacks: test_rows += len(df)
                        else: train_rows += len(df)
                    
                    total_rows += len(derived)
                    if i % 20 == 0:
                        logger.info(f"{os.path.basename(fpath)}: processed {i} chunks; total_rows={total_rows}")
                    if max_rows and total_rows >= max_rows: return
                    
            except Exception as e:
                logger.warning(f"Skip {fpath}: {e}")
                
    process_files(train_files, train_path, keep_attacks=False)
    process_files(test_files, test_path, keep_attacks=True)
    
    meta = {
        "total_rows": total_rows, "train_rows": train_rows, "test_rows": test_rows,
        "features": features, "generated": datetime.now().isoformat()
    }
    try:
        with open(os.path.join(output_dir, "meta.json"), "w") as f:
            json.dump(meta, f)
    except OSError as e:
        logger.warning(f"Could not write meta.json: {e}")
    
    logger.info(f"Preprocessing complete: {train_rows} train, {test_rows} test")
    return output_dir

class IDS:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.features = None
        
    def train(self, X_train, contamination=0.05, n_estimators=150, max_samples=256):
        logger.info(f"Training Isolation Forest: {n_estimators} estimators, contamination={contamination}")
        
        self.scaler = RobustScaler()
        X_scaled = self.scaler.fit_transform(X_train)
        
        # Normalize max_samples to acceptable values for sklearn:
        ms = max_samples
        if isinstance(ms, str):
            ms = 'auto' if ms == 'auto' else 'auto'
        elif isinstance(ms, float):
            # fraction (0,1]
            ms = float(ms)
            if not (0.0 < ms <= 1.0):
                ms = 'auto'
        elif isinstance(ms, (int, np.integer)):
            ms = int(ms)
            if ms < 1:
                ms = 1
            ms = min(ms, len(X_train))
        else:
            ms = 'auto'

        # Use single-threaded training to avoid memory duplication (more stable on large datasets)
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples=ms,
            random_state=42,
            n_jobs=1
        )
        self.model.fit(X_scaled)
        
        logger.info("Training complete")
        
    def predict(self, X):
        if self.model is None or self.scaler is None:
            raise ValueError("Model not trained")
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
    
    def decision_function(self, X):
        if self.model is None or self.scaler is None:
            raise ValueError("Model not trained")
        X_scaled = self.scaler.transform(X)
        return self.model.decision_function(X_scaled)
        
    def save(self, path):
        joblib.dump(self, path, compress=3)
        
    @classmethod  
    def load(cls, path):
        return joblib.load(path)

def _parse_contamination(val: str):
    v = str(val).strip().lower()
    if v == 'auto':
        return 'auto'
    try:
        f = float(v)
        if 0.0 < f < 0.5:
            return f
    except Exception:
        pass
    # Fallback sensible default for clean training
    return 'auto'

def _parse_max_samples(val: str, n_rows: int):
    v = str(val).strip().lower()
    if v == 'auto':
        return 'auto'
    try:
        if '%' in v:
            frac = float(v.replace('%',''))/100.0
            return min(max(frac, 1e-4), 1.0)
        f = float(v)
        if 0.0 < f <= 1.0:
            return f
        i = int(round(f))
        return min(max(i, 1), n_rows)
    except Exception:
        return 'auto'

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', nargs='+', required=True)
    parser.add_argument('--output', default='preprocessed')
    parser.add_argument('--model-output', default='model.joblib')
    parser.add_argument('--chunksize', type=int, default=100000)
    parser.add_argument('--max-rows', type=int)
    parser.add_argument('--contamination', type=str, default='auto')
    parser.add_argument('--n-estimators', type=int, default=150)
    parser.add_argument('--max-samples', type=str, default='auto', help="IsolationForest max_samples: 'auto', fraction (0-1], integer, or percent like '10%'")
    parser.add_argument('--train-rows', type=int, default=None, help='Train from at most N rows of train.csv using streaming chunks (avoids loading the full CSV).')
    parser.add_argument('--skip-preprocess', action='store_true', help='Skip preprocessing and use existing files in --output (expects train.csv)')
    # Evaluation controls: use decision_function thresholding instead of model.predict when provided
    parser.add_argument('--decision-threshold', type=float, default=None,
                        help='If set, classify as anomaly when decision_function(x) < threshold. Overrides model.predict for evaluation.')
    parser.add_argument('--target-fpr', type=float, default=None,
                        help='If set (0-1), calibrate a threshold on test.csv so that approximately this fraction of benign (label=0) are flagged. Overrides model.predict for evaluation.')
    args = parser.parse_args()
    
    if args.skip_preprocess:
        logger.info('Skipping preprocessing as requested (--skip-preprocess).')
    else:
        try:
            preprocess_data(args.input, args.output, args.chunksize, args.max_rows)
        except OSError as e:
            # If disk is full or similar, allow continuing to training if train.csv already exists.
            logger.warning(f"Preprocessing failed with OSError: {e}. Will attempt to continue if train.csv exists.")
    
    train_path = os.path.join(args.output, 'train.csv')
    if os.path.exists(train_path):
        # Load features for consistent column order
        features_path = os.path.join(args.output, 'features.json')
        if os.path.exists(features_path):
            with open(features_path, 'r') as f:
                features = json.load(f)
            # Read directly as float32 to reduce peak memory; label as int8
            dtypes = {c: np.float32 for c in features}
            dtypes['label'] = np.int8
            if args.train_rows is not None and args.train_rows > 0:
                # Stream-limited training: read only up to N rows via chunks
                target = int(args.train_rows)
                logger.info(f"Streaming training from {train_path}: target_rows={target}, chunksize={args.chunksize}")
                frames = []
                read_rows = 0
                for chunk in pd.read_csv(
                    train_path,
                    usecols=features + ['label'],
                    dtype=dtypes,
                    engine='c',
                    low_memory=False,
                    chunksize=max(1, min(args.chunksize, target)),
                ):
                    need = max(0, target - read_rows)
                    if need <= 0:
                        break
                    take = chunk.iloc[:need]
                    if not take.empty:
                        frames.append(take)
                        read_rows += len(take)
                    if read_rows >= target:
                        break
                if frames:
                    train_df = pd.concat(frames, ignore_index=True)
                else:
                    train_df = pd.DataFrame(columns=features + ['label'])
                logger.info(f"Streamed rows: {len(train_df)}")
            else:
                logger.info(f"Loading training data: {train_path} with {len(features)} features (float32)")
                train_df = pd.read_csv(
                    train_path,
                    usecols=features + ['label'],
                    dtype=dtypes,
                    engine='c',
                    low_memory=False,
                    memory_map=True
                )
        else:
            # Fallback: load then coerce to float32
            logger.info(f"Loading training data without features.json: {train_path}")
            if args.train_rows is not None and args.train_rows > 0:
                target = int(args.train_rows)
                logger.info(f"Streaming training from {train_path} (no features.json): target_rows={target}, chunksize={args.chunksize}")
                frames = []
                read_rows = 0
                for chunk in pd.read_csv(train_path, engine='c', low_memory=False, chunksize=max(1, min(args.chunksize, target))):
                    need = max(0, target - read_rows)
                    if need <= 0:
                        break
                    take = chunk.iloc[:need]
                    if not take.empty:
                        frames.append(take)
                        read_rows += len(take)
                    if read_rows >= target:
                        break
                train_df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
            else:
                train_df = pd.read_csv(train_path, engine='c', low_memory=False, memory_map=True)
            # Ensure numeric dtype and no NaNs (may use more memory)
            feature_cols = [c for c in train_df.columns if c != 'label']
            train_df[feature_cols] = train_df[feature_cols].apply(pd.to_numeric, errors='coerce').fillna(0).astype(np.float32)
            if 'label' in train_df.columns and train_df['label'].dtype != np.int8:
                try:
                    train_df['label'] = pd.to_numeric(train_df['label'], errors='coerce').fillna(0).astype(np.int8)
                except Exception:
                    train_df['label'] = 0
        # Basic load stats
        try:
            mem_gb = train_df.memory_usage(deep=True).sum() / 1e9
            logger.info(f"Loaded train.csv: rows={len(train_df)}, cols={len(train_df.columns)}, approx_mem={mem_gb:.2f} GB")
        except Exception:
            pass
        # Build X matrix without copy when possible
        feature_cols = features if 'features' in locals() else [c for c in train_df.columns if c != 'label']
        X_train = train_df[feature_cols].to_numpy(dtype=np.float32, copy=False)
        logger.info(f"Training matrix ready: shape={X_train.shape}, dtype={X_train.dtype}")
        
        ids = IDS()
        # Persist features inside the IDS object for single-object portability
        try:
            ids.features = features if 'features' in locals() else feature_cols
        except Exception:
            ids.features = feature_cols
        contamination = _parse_contamination(args.contamination)
        max_samples = _parse_max_samples(args.max_samples, len(X_train))
        ids.train(X_train, contamination, args.n_estimators, max_samples=max_samples)
        ids.save(args.model_output)
        # Save robust artifacts for forward compatibility
        root, ext = os.path.splitext(args.model_output)
        joblib.dump(ids.model, root + '_model.joblib', compress=3)
        joblib.dump(ids.scaler, root + '_scaler.joblib', compress=3)
        feat_src = os.path.join(args.output, 'features.json')
        if os.path.exists(feat_src):
            with open(feat_src, 'r') as f:
                joblib.dump(json.load(f), root + '_features.joblib', compress=3)
        logger.info(f"Model saved: {args.model_output}")
    
    test_path = os.path.join(args.output, 'test.csv')
    if os.path.exists(test_path) and os.path.exists(train_path):
        # Load test data with same feature order
        features_path = os.path.join(args.output, 'features.json')
        if os.path.exists(features_path):
            with open(features_path, 'r') as f:
                features = json.load(f)
            test_df = pd.read_csv(test_path, usecols=features + ['label'])
        else:
            test_df = pd.read_csv(test_path)
        # Ensure numeric dtype
        feature_cols = [c for c in test_df.columns if c != 'label']
        test_df[feature_cols] = test_df[feature_cols].apply(pd.to_numeric, errors='coerce').fillna(0).astype(np.float32)
        X_test = test_df[feature_cols].values
        y_test = test_df['label'].values
        
        # Decision scores: higher = more normal, lower = more anomalous
        decision_scores = ids.decision_function(X_test)
        # If thresholding is requested, use it; else fall back to model.predict
        threshold = None
        if args.target_fpr is not None:
            try:
                benign = decision_scores[test_df['label'].values == 0]
                if len(benign) > 0 and 0.0 < args.target_fpr < 1.0:
                    threshold = float(np.quantile(benign, args.target_fpr))
                    logger.info(f"Calibrated threshold for target_fpr={args.target_fpr:.4f}: threshold={threshold:.6f}")
                else:
                    logger.warning("Cannot calibrate threshold: no benign samples or invalid target_fpr; falling back.")
            except Exception as e:
                logger.warning(f"Threshold calibration failed: {e}; falling back.")
        elif args.decision_threshold is not None:
            threshold = float(args.decision_threshold)
            logger.info(f"Using provided decision threshold: {threshold:.6f}")

        if threshold is not None:
            pred_binary = (decision_scores < threshold).astype(int)
        else:
            predictions = ids.predict(X_test)
            pred_binary = (predictions == -1).astype(int)
        # Use inverted scores for AUCs so that higher = more anomalous
        scores = -decision_scores
        
        accuracy = (pred_binary == y_test).mean()
        tp = ((pred_binary == 1) & (y_test == 1)).sum()
        fp = ((pred_binary == 1) & (y_test == 0)).sum()
        fn = ((pred_binary == 0) & (y_test == 1)).sum()

        p, r, f1, _ = precision_recall_fscore_support(y_test, pred_binary, average='binary', zero_division=0)
        # AUCs only if both classes present
        try:
            roc = roc_auc_score(y_test, scores)
        except Exception:
            roc = float('nan')
        try:
            pr_auc = average_precision_score(y_test, scores)
        except Exception:
            pr_auc = float('nan')
        cm = confusion_matrix(y_test, pred_binary, labels=[0,1])

        # FPR for visibility when using thresholds
        try:
            tn, fp = cm[0]
            fpr = fp / max(1, (tn + fp))
        except Exception:
            fpr = float('nan')
        if threshold is not None:
            logger.info(f"Results: Acc={accuracy:.3f}, Prec={p:.3f}, Rec={r:.3f}, F1={f1:.3f}, ROC-AUC={roc:.3f}, PR-AUC={pr_auc:.3f}, FPR={fpr:.3f}, Thr={threshold:.6f}")
        else:
            logger.info(f"Results: Acc={accuracy:.3f}, Prec={p:.3f}, Rec={r:.3f}, F1={f1:.3f}, ROC-AUC={roc:.3f}, PR-AUC={pr_auc:.3f}")
        logger.info(f"Confusion Matrix [[TN, FP],[FN, TP]]: {cm.tolist()}")

if __name__ == "__main__":
    main()
