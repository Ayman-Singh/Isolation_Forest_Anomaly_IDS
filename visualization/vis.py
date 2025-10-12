#!/usr/bin/env python3
import joblib
import sys
import os
import argparse

# Ensure repository root is on sys.path so imports from project root work when
# running this file as a script (python3 visualization/vis.py)
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

# Best-effort: ensure model_script.IDS is available for unpickling
try:
    import model_script as _ms
    import __main__ as _main
    if not hasattr(_main, 'IDS') and hasattr(_ms, 'IDS'):
        _main.IDS = _ms.IDS
except Exception:
    pass

# Load your model (relative path)
model_path = os.path.join(os.path.dirname(__file__), '..', 'ugr16_if_stream_ms16384_20251003_181922.joblib')
model_path = os.path.abspath(model_path)

# Prefer using model_script.IDS.load when possible to avoid unpickle name issues
model = None
try:
    import model_script
    if hasattr(model_script, 'IDS') and hasattr(model_script.IDS, 'load'):
        # Some models were pickled when IDS lived in __main__; ensure unpickler can find it.
        prev_main = sys.modules.get('__main__')
        try:
            sys.modules['__main__'] = model_script
            model = model_script.IDS.load(model_path)
        finally:
            if prev_main is not None:
                sys.modules['__main__'] = prev_main
            else:
                del sys.modules['__main__']
except Exception:
    # fall back to raw joblib.load; try mapping __main__ to model_script during unpickle
    try:
        import model_script as _ms
        prev_main = sys.modules.get('__main__')
        try:
            sys.modules['__main__'] = _ms
            model = joblib.load(model_path)
        finally:
            if prev_main is not None:
                sys.modules['__main__'] = prev_main
            else:
                del sys.modules['__main__']
    except Exception as e:
        # re-raise with context
        raise RuntimeError(f"Failed to load model {model_path}: {e}") from e

if model is None:
    raise RuntimeError(f"Failed to load model: {model_path}")

# Defer heavy imports until after model loading
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA

# Preferred: load the preprocessed train.csv which contains the exact features (including label)
preproc_train = os.path.join(os.path.dirname(__file__), '..', 'UGR16_preprocessed', 'production_train', 'train.csv')
preproc_train = os.path.abspath(preproc_train)

# Exact feature list as in train.csv (order matters)
features = ['duration','packets','bytes','bps','pps','log_bytes','log_packets',
            'tcp','udp','icmp','fin','syn','rst','psh','ack','urg',
            'src_port','src_low','src_high','dst_port','dst_low','dst_high']

if os.path.exists(preproc_train):
    # load a sample of the preprocessed CSV (has label as last column)
    df = pd.read_csv(preproc_train, usecols=features + ['label'], nrows=100000)
    # keep labels if needed; for visualization we drop label for X
    X = df[features].astype(np.float32, copy=False)
else:
    # Fall back: derive features from raw UGR-16 CSV exactly like model_script does
    raw_path = os.path.join(os.path.dirname(__file__), '..', 'UGR-16_dataset', 'April', 'april.week3.first10M.csv')
    raw_path = os.path.abspath(raw_path)
    # read raw headerless with standard UGR16 ordering
    raw_cols = ["timestamp","duration","src_ip","dst_ip","src_port","dst_port","protocol","flags","tos","fwd","packets","bytes","label"]
    raw = pd.read_csv(raw_path, header=None, names=raw_cols, sep=',', on_bad_lines='skip', engine='c', low_memory=False, nrows=100000)
    # derive features using exact helpers from model_script
    try:
        import model_script
        mapping = {k: model_script.find_col(raw.columns, v) for k, v in model_script.COLS.items()}
        derived = model_script.derive_features(raw, mapping)
        # ensure full feature set and order
        for f in features:
            if f not in derived.columns:
                derived[f] = 0.0
        X = derived[features].astype(np.float32, copy=False)
    except Exception:
        # final fallback: try to read raw and select existing columns or zero-fill
        raw2 = pd.read_csv(raw_path, nrows=100000)
        for f in features:
            if f not in raw2.columns:
                raw2[f] = 0.0
        X = raw2[features].astype(np.float32, copy=False)

# Parse CLI args for thresholding and output
parser = argparse.ArgumentParser()
parser.add_argument('--decision-threshold', type=float, default=None,
                    help='Decision threshold on model.decision_function; samples with score < threshold are anomalies')
parser.add_argument('--out-dir', type=str, default=os.path.join(os.path.dirname(__file__)), help='Directory to write outputs')
args = parser.parse_args()

# Default decision threshold if none provided: use user-supplied value
DEFAULT_DECISION_THRESHOLD = -0.093570
decision_threshold = args.decision_threshold if args.decision_threshold is not None else DEFAULT_DECISION_THRESHOLD

# Scale features using the model's scaler when available. This matches training preprocessing.
X_scaled = None
try:
    if hasattr(model, 'scaler') and getattr(model, 'scaler') is not None:
        X_scaled = model.scaler.transform(X)
    else:
        # try to load an external scaler artifact alongside the model (root + '_scaler.joblib')
        root, _ = os.path.splitext(model_path)
        scaler_path = root + '_scaler.joblib'
        if os.path.exists(scaler_path):
            scaler = joblib.load(scaler_path)
            X_scaled = scaler.transform(X)
except Exception:
    X_scaled = None

if X_scaled is None:
    # fallback: standardize columns for visualization to avoid huge scale differences
    from sklearn.preprocessing import StandardScaler
    X_scaled = StandardScaler().fit_transform(X)

# Compute anomaly scores on scaled features
if hasattr(model, 'decision_function'):
    raw_scores = model.decision_function(X_scaled)
elif hasattr(model, 'model') and hasattr(model.model, 'decision_function'):
    raw_scores = model.model.decision_function(X_scaled)
else:
    raise RuntimeError('Loaded model does not expose decision_function')

# Convert to anomaly scores where larger means more anomalous
anomaly_scores = -raw_scores
anom_prob = (anomaly_scores - np.nanmin(anomaly_scores)) / (np.nanmax(anomaly_scores) - np.nanmin(anomaly_scores) + 1e-12)

# Reduce dimensions to 2D for visualization using scaled features
X_np = X_scaled if isinstance(X_scaled, (np.ndarray,)) else (X_scaled.values if hasattr(X_scaled, 'values') else np.asarray(X_scaled))
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_np)

# Prepare outputs
out_dir = os.path.abspath(args.out_dir)
os.makedirs(out_dir, exist_ok=True)
out_png_scores = os.path.join(out_dir, 'vis_scores.png')
out_png_thresh = os.path.join(out_dir, 'vis_threshold.png')
out_csv = os.path.join(out_dir, 'vis_data.csv')

# Plot 1: PCA scatter colored by anomaly score
plt.figure(figsize=(12,8))
sc = plt.scatter(X_pca[:,0], X_pca[:,1], c=anomaly_scores, cmap='coolwarm', s=8, rasterized=True)
plt.colorbar(sc, label='Anomaly Score (higher = more anomalous)')
plt.title('Isolation Forest: 2D PCA projection colored by anomaly score')
plt.xlabel('PCA Component 1')
plt.ylabel('PCA Component 2')
plt.tight_layout()
plt.savefig(out_png_scores, dpi=150)
plt.close()

# Apply decision threshold (on decision_function space): anomaly if decision_score < threshold
decision_scores = raw_scores
pred_binary = (decision_scores < decision_threshold).astype(int)

# Plot 2: PCA scatter with anomalies highlighted
plt.figure(figsize=(12,8))
normal_idx = pred_binary == 0
anom_idx = pred_binary == 1
plt.scatter(X_pca[normal_idx,0], X_pca[normal_idx,1], c='lightgrey', s=6, label='normal')
plt.scatter(X_pca[anom_idx,0], X_pca[anom_idx,1], c='red', s=10, label='anomaly', edgecolors='k')
plt.legend()
plt.title(f'Isolation Forest: anomalies (decision_threshold={decision_threshold:.6f})')
plt.xlabel('PCA Component 1')
plt.ylabel('PCA Component 2')
plt.tight_layout()
plt.savefig(out_png_thresh, dpi=150)
plt.close()

# Save CSV with PCA coords, decision score, anomaly flag and (if available) label
labels = None
try:
    if 'label' in df.columns:
        labels = df['label'].astype(str).values
    elif 'raw' in locals() and 'label' in raw.columns:
        labels = raw['label'].astype(str).values
except Exception:
    labels = None

import csv
with open(out_csv, 'w', newline='') as f:
    w = csv.writer(f)
    header = ['pca1','pca2','decision_score','anomaly']
    if labels is not None:
        header.append('label')
    w.writerow(header)
    for i in range(X_pca.shape[0]):
        row = [float(X_pca[i,0]), float(X_pca[i,1]), float(decision_scores[i]), int(pred_binary[i])]
        if labels is not None and i < len(labels):
            row.append(labels[i])
        w.writerow(row)

print(f"Saved visualization images: {out_png_scores}, {out_png_thresh}")
print(f"Saved data CSV: {out_csv}")
