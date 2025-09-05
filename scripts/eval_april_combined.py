import os, sys, json, numpy as np, pandas as pd, joblib
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, average_precision_score, confusion_matrix
# Ensure unpickling resolves IDS from model_script
import importlib
ms = importlib.import_module('model_script')
sys.modules['__main__'] = ms

MODEL = sys.argv[1] if len(sys.argv) > 1 else 'models/ugr16_if_ms16384_c005_10M_20250905_055527.joblib'
TEST = sys.argv[2] if len(sys.argv) > 2 else 'UGR16_preprocessed/april_eval/test.csv'
FEAT = sys.argv[3] if len(sys.argv) > 3 else 'UGR16_preprocessed/production_train/features.json'

print('USING_MODEL', MODEL)
ids = joblib.load(MODEL)  # combined artifact
with open(FEAT,'r') as f:
    features = json.load(f)
usecols = features + ['label']
dtypes = {c: np.float32 for c in features}; dtypes['label'] = np.int8

y_true_parts = []
y_pred_parts = []
score_parts = []
for ch in pd.read_csv(TEST, usecols=usecols, dtype=dtypes, engine='c', low_memory=False, chunksize=200_000):
    X = ch[features].to_numpy(np.float32, copy=False)
    y = ch['label'].to_numpy(np.int8, copy=False)
    pred = (ids.predict(X) == -1).astype(np.int8)
    sc = -ids.decision_function(X)
    y_true_parts.append(y)
    y_pred_parts.append(pred)
    score_parts.append(sc)
    print(f'Chunk done: n={len(ch)}', flush=True)

y_true = np.concatenate(y_true_parts) if y_true_parts else np.array([], dtype=np.int8)
y_pred = np.concatenate(y_pred_parts) if y_pred_parts else np.array([], dtype=np.int8)
scores = np.concatenate(score_parts) if score_parts else np.array([], dtype=np.float32)
print('Rows evaluated:', len(y_true))

p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
cm = confusion_matrix(y_true, y_pred, labels=[0,1])
try:
    roc = roc_auc_score(y_true, scores)
except Exception:
    roc = float('nan')
try:
    pr_auc = average_precision_score(y_true, scores)
except Exception:
    pr_auc = float('nan')
print({'acc': float((y_pred==y_true).mean()), 'prec': float(p), 'rec': float(r), 'f1': float(f1), 'roc_auc': float(roc), 'pr_auc': float(pr_auc), 'cm': cm.tolist()})
