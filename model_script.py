import pandas as pd
import numpy as np
from datetime import datetime
import gc
import os
import logging
from typing import Optional, Tuple, List, Dict, Any
import warnings
import argparse
from collections import deque

warnings.filterwarnings('ignore')

"""Anomaly detection on UGR16 with an Isolation Forest implementation."""

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('anomaly_detection.log'),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


class RobustScaler:
    """Robust + MinMax scaler with feature selection baked in.

    - Fits on normal-only data.
    - Drops near-constant features and remembers a mask.
    - Uses IQR-based scaling when possible, else MinMax.
    - Ensures consistent transform at train/test/inference time.
    """

    def __init__(self, var_eps: float = 1e-10, iqr_eps: float = 1e-8):
        self.var_eps = var_eps
        self.iqr_eps = iqr_eps
        self.fitted: bool = False
        self.feature_mask: Optional[np.ndarray] = None
        self.median_vals: Optional[np.ndarray] = None
        self.iqr_vals: Optional[np.ndarray] = None
        self.min_vals: Optional[np.ndarray] = None
        self.max_vals: Optional[np.ndarray] = None
        self.use_robust: Optional[np.ndarray] = None

    def fit(self, X: np.ndarray) -> "RobustScaler":
        # Remove constant/near-constant features
        vars_ = np.var(X, axis=0)
        self.feature_mask = vars_ > self.var_eps
        Xf = X[:, self.feature_mask] if np.any(self.feature_mask) else X

        # Compute robust stats on filtered features
        q25 = np.percentile(Xf, 25, axis=0)
        q75 = np.percentile(Xf, 75, axis=0)
        iqr = q75 - q25
        med = np.median(Xf, axis=0)
        mn = np.min(Xf, axis=0)
        mx = np.max(Xf, axis=0)

        self.median_vals = med
        self.iqr_vals = iqr
        self.min_vals = mn
        self.max_vals = mx
        self.use_robust = iqr > self.iqr_eps
        self.fitted = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        if not self.fitted:
            raise ValueError("Scaler not fitted")

        X = np.nan_to_num(X, nan=0.0)
        X = np.where(np.isfinite(X), X, 0.0)
        Xf = X[:, self.feature_mask] if np.any(self.feature_mask) else X

        out = np.zeros_like(Xf, dtype=float)

        # Robust scaling
        if np.any(self.use_robust):
            rmask = self.use_robust
            out[:, rmask] = (Xf[:, rmask] - self.median_vals[rmask]) / (self.iqr_vals[rmask] + 1e-8)
            out[:, rmask] = np.clip(out[:, rmask], -3.0, 3.0)
            out[:, rmask] = (out[:, rmask] + 3.0) / 6.0

        # MinMax fallback
        mmmask = ~self.use_robust
        if np.any(mmmask):
            rng = self.max_vals[mmmask] - self.min_vals[mmmask]
            rng[rng == 0] = 1.0
            out[:, mmmask] = (Xf[:, mmmask] - self.min_vals[mmmask]) / rng
            out[:, mmmask] = np.clip(out[:, mmmask], 0.0, 1.0)

        return out

    def get_params(self) -> Dict[str, Any]:
        return {
            'feature_mask': self.feature_mask,
            'median_vals': self.median_vals,
            'iqr_vals': self.iqr_vals,
            'min_vals': self.min_vals,
            'max_vals': self.max_vals,
            'use_robust': self.use_robust,
        }


class IsolationTree:
    """Isolation tree used for unsupervised anomaly detection"""

    def __init__(self, max_depth: int = None, random_state: int = 42):
        # Adaptive depth based on data size: ceil(log2(max_samples)) + 1
        self.max_depth = max_depth if max_depth is not None else 15  # Increased default
        self.random_state = random_state
        self.tree = None

    def _random_split(self, X: np.ndarray) -> Tuple[Optional[int], Optional[float]]:
        """Generate random split point with improved feature selection"""
        n_features = X.shape[1]
        
        # Enhanced feature selection: prefer features with higher variance
        if X.shape[0] > 1:
            feature_vars = np.var(X, axis=0)
            # Avoid zero variance features
            valid_features = np.where(feature_vars > 1e-8)[0]
            if len(valid_features) == 0:
                return None, None
            
            # Weighted selection favoring high-variance features
            weights = feature_vars[valid_features]
            weights = weights / np.sum(weights)
            feature_idx = np.random.choice(valid_features, p=weights)
        else:
            feature_idx = np.random.randint(0, n_features)
        
        feature_values = X[:, feature_idx]
        min_val = np.min(feature_values)
        max_val = np.max(feature_values)
        
        if min_val == max_val:
            return None, None
        
        # More robust threshold selection
        # Use interquartile range to avoid extreme outliers
        q25, q75 = np.percentile(feature_values, [25, 75])
        if q75 > q25:
            threshold = np.random.uniform(q25, q75)
        else:
            threshold = np.random.uniform(min_val, max_val)
            
        return feature_idx, threshold

    def _build_tree(self, X: np.ndarray, depth: int = 0) -> Dict[str, Any]:
        """Build isolation tree recursively"""
        n_samples = X.shape[0]

        # Stopping conditions
        if depth >= self.max_depth or n_samples <= 1:
            return {
                'type': 'leaf',
                'size': n_samples,
                'depth': depth,
            }

        # Generate random split
        feature, threshold = self._random_split(X)
        if feature is None:
            return {
                'type': 'leaf',
                'size': n_samples,
                'depth': depth,
            }

        # Split data
        left_mask = X[:, feature] <= threshold
        right_mask = ~left_mask

        # Create node
        node = {
            'type': 'node',
            'feature': feature,
            'threshold': threshold,
            'depth': depth,
            'left': self._build_tree(X[left_mask], depth + 1),
            'right': self._build_tree(X[right_mask], depth + 1),
        }
        return node

    def fit(self, X: np.ndarray) -> 'IsolationTree':
        """Train the isolation tree (unsupervised) with enhanced splitting"""
        np.random.seed(self.random_state)
        self.tree = self._build_tree(X)
        return self

    def _path_length(self, x: np.ndarray, node: Dict[str, Any], depth: int = 0) -> float:
        """Calculate normalized path length (adds expected adjustment for leaf size)"""
        if node['type'] == 'leaf':
            size = max(1, node.get('size', 1))
            if size <= 1:
                return depth
            # Expected path length adjustment for leaf samples
            c = 2 * (np.log(size - 1) + 0.5772156649) - (2 * (size - 1) / size)
            return depth + c

        if x[node['feature']] <= node['threshold']:
            return self._path_length(x, node['left'], depth + 1)
        else:
            return self._path_length(x, node['right'], depth + 1)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly scores (lower = more anomalous)"""
        if self.tree is None:
            raise ValueError("Model not trained yet. Call fit() first.")

        path_lengths = []
        for x in X:
            path_length = self._path_length(x, self.tree)
            path_lengths.append(path_length)
        return np.array(path_lengths)


class IsolationForest:
    """Isolation Forest for unsupervised network traffic anomaly detection

    Enhanced with streaming-friendly threshold adaptation.

    Score semantics: higher score => more anomalous (shorter average path).
    """

    __slots__ = (
        "n_estimators",
        "max_samples",
        "contamination",
        "random_state",
        "trees",
        "normalization_factor",
        "adaptive",
        "adaptive_target_fpr",
        "score_buffer_size",
        "_recent_normal_scores",
        "dynamic_threshold",
        "score_mean",
        "score_std",
        "_c_subsample",
    )

    def __init__(
        self,
        n_estimators: int = 100,
        max_samples: int = 256,
        contamination: float = 0.1,
        random_state: int = 42,
        adaptive: bool = True,
        adaptive_target_fpr: float = 0.05,
        score_buffer_size: int = 5000,
    ):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.trees = []
        self.normalization_factor = None
        self.adaptive = adaptive
        self.adaptive_target_fpr = adaptive_target_fpr
        self.score_buffer_size = score_buffer_size
        self._recent_normal_scores: deque = deque(maxlen=score_buffer_size)
        self.dynamic_threshold: Optional[float] = None
        self.score_mean: Optional[float] = None
        self.score_std: Optional[float] = None
        self._c_subsample: Optional[float] = None  # expected path length for subsample size

    def _expected_path_length(self, sample_size: int) -> float:
        if sample_size <= 1:
            return 0.0
        return 2.0 * (np.log(sample_size - 1) + 0.5772156649) - (2.0 * (sample_size - 1) / sample_size)

    def _sample_data(self, X: np.ndarray) -> np.ndarray:
        """Sample data for tree construction"""
        n_samples = X.shape[0]
        sample_size = min(self.max_samples, n_samples)
        indices = np.random.choice(n_samples, size=sample_size, replace=False)
        return X[indices]

    def fit(self, X: np.ndarray) -> 'IsolationForest':
        """Train the isolation forest on normal data only with enhanced diversity"""
        logger.info(f"Training Isolation Forest with {self.n_estimators} trees")
        logger.info(f"Training on {len(X)} normal samples only")
        np.random.seed(self.random_state)

        # Adaptive max_samples based on dataset size
        optimal_samples = min(self.max_samples, max(64, int(np.sqrt(X.shape[0]))))
        self.max_samples = optimal_samples
        logger.info(f"Using adaptive max_samples: {self.max_samples}")

        # Precompute expected path length for subsample size
        self._c_subsample = self._expected_path_length(self.max_samples)

        # Build trees with enhanced diversity
        self.trees = []
        for i in range(self.n_estimators):
            # Adaptive depth based on subsample size
            adaptive_depth = max(8, int(np.log2(self.max_samples)) + 3)
            
            tree = IsolationTree(
                max_depth=adaptive_depth, 
                random_state=self.random_state + i * 1000  # Better seed separation
            )
            
            # Enhanced sampling (random or bootstrap)
            sample_data = self._sample_data_enhanced(X, i)
            tree.fit(sample_data)
            self.trees.append(tree)

        # Improved normalization factor
        self.normalization_factor = self._c_subsample if self._c_subsample and self._c_subsample > 0 else 1.0
        logger.info(f"Normalization factor: {self.normalization_factor:.4f}")
        return self

    def _sample_data_enhanced(self, X: np.ndarray, tree_idx: int) -> np.ndarray:
        """Enhanced sampling with better diversity (random or bootstrap)."""
        n_samples = X.shape[0]
        sample_size = min(self.max_samples, n_samples)
        if tree_idx % 2 == 0:
            idx = np.random.choice(n_samples, size=sample_size, replace=False)
        else:
            idx = np.random.choice(n_samples, size=sample_size, replace=True)
        return X[idx]

    # Removed unused _calculate_normalization_factor

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Compute anomaly scores (higher score = more anomalous).

        Uses normalized path lengths with correct Isolation Forest formula.
        Returns scores in range [0,1] where values close to 1 are anomalies.
        """
        if not self.trees:
            raise ValueError("Model not trained yet. Call fit() first.")

        all_path_lengths = []
        for tree in self.trees:
            all_path_lengths.append(tree.predict(X))
        avg_path_lengths = np.mean(all_path_lengths, axis=0)
        
        # Correct Isolation Forest anomaly score formula
        norm_factor = self.normalization_factor if self.normalization_factor and self.normalization_factor > 0 else 1.0
        
        # Standard IF formula: s(x,n) = 2^(-E(h(x))/c(n))
        # But we want higher scores for anomalies, so we use: 1 - 2^(-E(h(x))/c(n))
        raw_scores = 2 ** (-avg_path_lengths / norm_factor)
        
        # Invert so that anomalies (short paths) get higher scores
        anomaly_scores = 1.0 - raw_scores
        
        # Ensure scores are in [0,1] range
        anomaly_scores = np.clip(anomaly_scores, 0.0, 1.0)
        
        return anomaly_scores

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Alias for predict() for integration clarity."""
        return self.predict(X)

    def update_score_distribution(self, normal_scores: np.ndarray):
        """Update running distribution stats with new presumed-normal scores."""
        if normal_scores.size == 0:
            return
            
        # Add scores to buffer
        self._recent_normal_scores.extend(normal_scores.tolist())
        arr = np.fromiter(self._recent_normal_scores, dtype=float)
        
        # Robust statistics using trimmed mean/std
        # Remove extreme outliers (top/bottom 5%) for more stable estimates
        if arr.size > 20:  # Need sufficient samples
            trimmed_arr = np.sort(arr)[int(0.05*len(arr)):int(0.95*len(arr))]
            self.score_mean = float(trimmed_arr.mean())
            self.score_std = float(trimmed_arr.std(ddof=1)) if trimmed_arr.size > 1 else 0.0
        else:
            self.score_mean = float(arr.mean())
            self.score_std = float(arr.std(ddof=1)) if arr.size > 1 else 0.0

        # Enhanced adaptive threshold with temporal smoothing
        if self.adaptive and arr.size > 10:
            # Use robust quantile estimation
            target_high_quantile = 1.0 - float(self.adaptive_target_fpr)
            new_threshold = float(np.quantile(arr, target_high_quantile))
            
            # Temporal smoothing to prevent threshold oscillations
            if self.dynamic_threshold is not None:
                smoothing_factor = 0.1  # Adjust based on adaptation speed needs
                self.dynamic_threshold = (1 - smoothing_factor) * self.dynamic_threshold + smoothing_factor * new_threshold
            else:
                self.dynamic_threshold = new_threshold
                
            # Ensure threshold is reasonable (between mean and mean + 3*std)
            if self.score_std > 0:
                min_threshold = self.score_mean
                max_threshold = self.score_mean + 3 * self.score_std
                self.dynamic_threshold = np.clip(self.dynamic_threshold, min_threshold, max_threshold)

    def get_anomaly_threshold(self, fallback_threshold: float) -> float:
        """Return dynamic threshold if available else fallback."""
        return self.dynamic_threshold if self.dynamic_threshold is not None else fallback_threshold

    def is_anomaly(self, scores: np.ndarray, base_threshold: float) -> np.ndarray:
        """Vectorized anomaly decision using dynamic threshold if present."""
        thresh = self.get_anomaly_threshold(base_threshold)
        return scores >= thresh

    def partial_refit(self, X_new: np.ndarray, replace_fraction: float = 0.2):
        """Replace a fraction of trees with new ones trained on recent normal data (concept drift adaptation)."""
        if not self.trees:
            raise ValueError("Model not trained yet")

        n_replace = max(1, int(len(self.trees) * replace_fraction))
        indices = np.random.choice(len(self.trees), size=n_replace, replace=False)
        for idx in indices:
            adaptive_depth = max(8, int(np.log2(self.max_samples)) + 3)
            tree = IsolationTree(max_depth=adaptive_depth, random_state=self.random_state + np.random.randint(0, 1_000_000))
            sample_data = self._sample_data_enhanced(X_new, idx)
            tree.fit(sample_data)
            self.trees[idx] = tree

        # Optionally update normalization factor to reflect blended data size
        self.normalization_factor = self._c_subsample if self._c_subsample else self._expected_path_length(
            min(self.max_samples, X_new.shape[0])
        )

        # After refit, optionally refresh threshold stats using new trees
        new_scores = self.predict(X_new)
        self.update_score_distribution(new_scores)


class UGR16AnomalyDetector:
    """UGR16 network traffic anomaly detection using Isolation Forest.

    Defines attacks using core attack labels (excluding 'labelblacklist').
    """

    def __init__(self, variant: str = 'v1'):
        self.variant = variant
        self.isolation_forest = None  # type: Optional[IsolationForest]
        self.feature_names = None  # type: Optional[List[str]]
        self.training_time = None  # type: Optional[float]
        self.anomaly_threshold = None  # type: Optional[float]
        self.scaler_params = None  # type: Optional[Dict[str, np.ndarray]]
        self.scaler = None  # type: Optional[RobustScaler]
        self.pseudo_normal_used = False  # retained for compatibility; will stay False now

    def load_ugr16_data(self) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Load UGR16 dataset"""
        logger.info(f"Loading UGR16 dataset variant: {self.variant}")

        # Load training data
        X_train_file = f'UGR16_FeatureData/csv/UGR16{self.variant}.Xtrain.csv'
        Y_train_file = f'UGR16_FeatureData/csv/UGR16{self.variant}.Ytrain.csv'

        # Load test data
        X_test_file = f'UGR16_FeatureData/csv/UGR16{self.variant}.Xtest.csv'
        Y_test_file = f'UGR16_FeatureData/csv/UGR16{self.variant}.Ytest.csv'

        # Check if files exist
        if not all(os.path.exists(f) for f in [X_train_file, Y_train_file, X_test_file, Y_test_file]):
            raise FileNotFoundError(f"UGR16 {self.variant} files not found")

        # Load data
        X_train = pd.read_csv(X_train_file, index_col=0)
        Y_train = pd.read_csv(Y_train_file, index_col=0)
        X_test = pd.read_csv(X_test_file, index_col=0)
        Y_test = pd.read_csv(Y_test_file, index_col=0)

        logger.info(f"Loaded UGR16 {self.variant}:")
        logger.info(f" X_train: {X_train.shape}")
        logger.info(f" Y_train: {Y_train.shape}")
        logger.info(f" X_test: {X_test.shape}")
        logger.info(f" Y_test: {Y_test.shape}")
        return X_train, Y_train, X_test, Y_test

    def preprocess_for_anomaly_detection(
        self,
        X_train: pd.DataFrame,
        Y_train: pd.DataFrame,
        X_test: pd.DataFrame,
        Y_test: pd.DataFrame,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Preprocess UGR16 data for anomaly detection.

        Normal = rows with zero counts across core attack labels (excluding 'labelblacklist').
        Attack = any row with a non-zero count in those core attack labels.
        """

        logger.info("Preprocessing UGR16 data (core attack labels define anomalies)")
        core_attack_labels = [c for c in Y_train.columns if c != 'labelblacklist']
        if not core_attack_labels:
            raise ValueError("No attack label columns found (excluding 'labelblacklist')")

        # Determine binary labels
        train_attack_vector = (Y_train[core_attack_labels].sum(axis=1) > 0).astype(int)
        test_attack_vector = (Y_test[core_attack_labels].sum(axis=1) > 0).astype(int)

        logger.info(
            f"Training data - Normal: {(train_attack_vector==0).sum()}, Attacks: {(train_attack_vector==1).sum()}"
        )
        logger.info(
            f"Test data - Normal: {(test_attack_vector==0).sum()}, Attacks: {(test_attack_vector==1).sum()}"
        )
        if (train_attack_vector == 0).sum() == 0:
            raise ValueError("No normal samples found in training set with current core attack label definition.")

        # Masks
        train_normal_mask = (train_attack_vector == 0)
        test_normal_mask = (test_attack_vector == 0)

        # Separate
        X_train_normal = X_train[train_normal_mask].values
        X_train_attack = X_train[~train_normal_mask].values
        X_test_normal = X_test[test_normal_mask].values
        X_test_attack = X_test[~test_normal_mask].values

        # Fit robust scaler on true-normal only, apply consistently
        logger.info("Fitting robust scaler on true-normal data...")
        self.scaler = RobustScaler().fit(X_train_normal)
        X_train_normal = self.scaler.transform(X_train_normal)
        X_train_attack = self.scaler.transform(X_train_attack) if X_train_attack.size else X_train_attack
        X_test_normal = self.scaler.transform(X_test_normal)
        X_test_attack = self.scaler.transform(X_test_attack) if X_test_attack.size else X_test_attack

        self.feature_names = X_train.columns.tolist()
        self.scaler_params = self.scaler.get_params()

        logger.info("Preprocessed data shapes (true normal definition):")
        logger.info(f" Train normal: {X_train_normal.shape}")
        logger.info(f" Train attack: {X_train_attack.shape}")
        logger.info(f" Test normal: {X_test_normal.shape}")
        logger.info(f" Test attack: {X_test_attack.shape}")
        return X_train_normal, X_train_attack, X_test_normal, X_test_attack

    def train_anomaly_detector(
        self,
        X_train_normal: np.ndarray,
        n_estimators: int = 50,
        contamination: float = 0.1,
        adaptive: bool = True,
        adaptive_target_fpr: float = 0.05,
    ) -> None:
        """Train anomaly detector with enhanced validation and optimization."""
        logger.info("Training enhanced anomaly detector on normal data only")
        start_time = datetime.now()

        # Input validation and preprocessing
        if X_train_normal.shape[0] < 100:
            logger.warning(f"Training set very small ({X_train_normal.shape[0]} samples). Consider more data.")
        
        # Feature selection already applied by scaler; keep dimensions as-is
        self.active_features = self.scaler.feature_mask if hasattr(self, 'scaler') else None

        # Enhanced Isolation Forest with better parameters
        self.isolation_forest = IsolationForest(
            n_estimators=max(n_estimators, 100),  # Ensure minimum trees for stability
            max_samples=min(512, max(64, int(np.sqrt(X_train_normal.shape[0])))),  # Adaptive sampling
            contamination=contamination,
            random_state=42,
            adaptive=adaptive,
            adaptive_target_fpr=adaptive_target_fpr,
        )
        
        self.isolation_forest.fit(X_train_normal)
        self.training_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"Enhanced anomaly detector trained in {self.training_time:.2f} seconds")

        # Enhanced threshold computation with cross-validation
        train_scores = self.isolation_forest.predict(X_train_normal)
        
        # Use more robust threshold estimation
        # Multiple quantiles for robustness
        quantiles = [0.90, 0.95, 0.99]
        contamination_levels = [0.10, 0.05, 0.01]
        
        best_threshold = None
        best_score = float('-inf')
        
        for q, c in zip(quantiles, contamination_levels):
            if abs(c - contamination) < 0.02:  # Close to target contamination
                threshold_candidate = float(np.quantile(train_scores, q))
                
                # Score based on separation between normal scores and threshold
                separation = threshold_candidate - np.mean(train_scores)
                stability = -np.std(train_scores[train_scores < threshold_candidate])  # Lower std is better
                score = separation + stability
                
                if score > best_score:
                    best_score = score
                    best_threshold = threshold_candidate
        
        self.anomaly_threshold = best_threshold if best_threshold is not None else float(np.quantile(train_scores, 1.0 - contamination))
        
        # Initialize adaptive threshold system
        self.isolation_forest.update_score_distribution(train_scores)
        
        logger.info(f"Static anomaly threshold: {self.anomaly_threshold:.4f}")
        logger.info(f"Training score stats - Mean: {np.mean(train_scores):.4f}, Std: {np.std(train_scores):.4f}")
        
        if self.isolation_forest.dynamic_threshold is not None:
            logger.info(f"Initial dynamic threshold (FPR {adaptive_target_fpr:.2%}): {self.isolation_forest.dynamic_threshold:.4f}")
        
        # Validation: Check that threshold makes sense
        anomaly_rate = np.mean(train_scores >= self.anomaly_threshold)
        logger.info(f"Training anomaly rate with threshold: {anomaly_rate:.2%} (target: {contamination:.2%})")
        
        if anomaly_rate > contamination * 2:
            logger.warning("Threshold may be too low - high false positive rate expected")
        elif anomaly_rate < contamination * 0.5:
            logger.warning("Threshold may be too high - low sensitivity expected")

    def transform_features(self, features: np.ndarray) -> np.ndarray:
        """Scale raw feature vector(s) using the fitted robust scaler."""
        if not hasattr(self, 'scaler') or self.scaler is None:
            raise ValueError("Scaler not available; call preprocess_for_anomaly_detection first")
        feats = features if features.ndim == 2 else features.reshape(1, -1)
        return self.scaler.transform(feats)

    def score(self, scaled_features: np.ndarray) -> np.ndarray:
        """Return anomaly scores for scaled feature matrix."""
        if self.isolation_forest is None:
            raise ValueError("Model not trained")
        return self.isolation_forest.predict(scaled_features)

    def infer(self, raw_features: np.ndarray, update_distribution: bool = True) -> Dict[str, Any]:
        """Enhanced inference with production optimizations (anomaly if score >= threshold)."""
        if self.isolation_forest is None:
            raise ValueError("Model not trained")
            
        # Input validation for production safety
        if raw_features.size == 0:
            return {'scores': np.array([]), 'threshold': 0.5, 'anomalies': np.array([]), 'anomaly_indices': np.array([])}
        
        # Ensure proper shape
        if raw_features.ndim == 1:
            raw_features = raw_features.reshape(1, -1)
        
        # Feature transformation with error handling
        try:
            scaled = self.transform_features(raw_features)
        except Exception as e:
            logger.error(f"Feature transformation failed: {e}")
            # Fallback: basic normalization
            scaled = np.clip(raw_features, 0, 1)
        
        # Anomaly scoring
        scores = self.score(scaled)
        threshold = self.isolation_forest.get_anomaly_threshold(
            float(self.anomaly_threshold) if self.anomaly_threshold is not None else 0.5
        )
        
        # Anomaly detection with confidence scoring
        anomalies = scores >= threshold
        
        # Compute confidence scores (distance from threshold)
        confidence = np.abs(scores - threshold) / max(threshold, 1e-6)
        
        # Adaptive threshold update (only for normal-looking samples)
        if update_distribution and self.isolation_forest and scores.ndim == 1:
            # Only update with high-confidence normal samples to prevent contamination
            normal_mask = ~anomalies
            high_confidence_normal = normal_mask & (confidence > 0.1)  # Sufficient distance from threshold
            
            if np.any(high_confidence_normal):
                normal_scores = scores[high_confidence_normal]
                self.isolation_forest.update_score_distribution(normal_scores)
        
        return {
            'scores': scores,
            'threshold': threshold,
            'anomalies': anomalies,
            'anomaly_indices': np.where(anomalies)[0],
            'confidence': confidence,
            'n_anomalies': np.sum(anomalies),
            'anomaly_rate': np.mean(anomalies),
        }

    def minimal_artifact(self) -> Dict[str, Any]:
        """Return minimal dictionary needed for real-time serving (for JSON/joblib)."""
        return {
            'variant': self.variant,
            'feature_names': self.feature_names,
            'scaler_params': self.scaler_params,
            'anomaly_threshold': self.anomaly_threshold,
            'dynamic_threshold': self.isolation_forest.dynamic_threshold if self.isolation_forest else None,
            'n_estimators': self.isolation_forest.n_estimators if self.isolation_forest else None,
            'timestamp': datetime.now().isoformat(),
        }

    def evaluate_anomaly_detector(
        self,
        X_test_normal: np.ndarray,
        X_test_attack: np.ndarray,
    ) -> Dict[str, float]:
        """Evaluate anomaly detector performance (binary). Anomaly if score >= threshold."""
        if self.isolation_forest is None:
            raise ValueError("Model not trained")
        normal_scores = self.isolation_forest.predict(X_test_normal)
        attack_scores = self.isolation_forest.predict(X_test_attack)
        threshold = self.isolation_forest.get_anomaly_threshold(
            float(self.anomaly_threshold) if self.anomaly_threshold is not None else 0.5
        )
        normal_anomalies = np.sum(normal_scores >= threshold)
        attack_detected = np.sum(attack_scores >= threshold)
        total_normal = len(normal_scores)
        total_attacks = len(attack_scores)
        true_negatives = total_normal - normal_anomalies
        false_positives = normal_anomalies
        false_negatives = total_attacks - attack_detected
        true_positives = attack_detected
        accuracy = (true_positives + true_negatives) / (total_normal + total_attacks) if (total_normal + total_attacks) > 0 else 0
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = false_positives / total_normal if total_normal > 0 else 0
        tpr = true_positives / total_attacks if total_attacks > 0 else 0

        logger.info("Anomaly Detection Performance (score >= threshold considered anomaly):")
        logger.info(f" Accuracy: {accuracy:.4f}")
        logger.info(f" Precision: {precision:.4f}")
        logger.info(f" Recall: {recall:.4f}")
        logger.info(f" F1 Score: {f1_score:.4f}")
        logger.info(f" False Positive Rate: {fpr:.4f}")
        logger.info(f" True Positive Rate: {tpr:.4f}")
        logger.info(f" Normal flagged: {normal_anomalies}/{total_normal} ({fpr:.2%}) Threshold: {threshold:.4f}")
        logger.info(f" Attacks detected: {attack_detected}/{total_attacks} ({tpr:.2%})")
        if self.pseudo_normal_used:
            logger.warning("Metrics computed using pseudo-normal heuristic subset (no explicit normal samples).")
        return {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1_score),
            'false_positive_rate': float(fpr),
            'true_positive_rate': float(tpr),
            'normal_anomalies': int(normal_anomalies),
            'attacks_detected': int(attack_detected),
            'total_normal': int(total_normal),
            'total_attacks': int(total_attacks),
        }

    def save_model(self, filepath: str) -> None:
        """Persist model with metadata for real-time inference."""
        if self.isolation_forest is None:
            raise ValueError("No model to save")
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        import joblib
        model_data = {
            'isolation_forest': self.isolation_forest,
            'anomaly_threshold': self.anomaly_threshold,
            'dynamic_threshold': self.isolation_forest.dynamic_threshold,
            'training_time': self.training_time,
            'variant': self.variant,
            'feature_names': self.feature_names,
            'scaler_params': self.scaler_params,
            'pseudo_normal_used': self.pseudo_normal_used,
            'timestamp': datetime.now().isoformat(),
        }
        joblib.dump(model_data, filepath, compress=3)
        logger.info(f"Model saved: {filepath}")

    def save_metrics(self, metrics: Dict[str, float], timestamp: Optional[str] = None) -> None:
        """Save metrics snapshot and append to history."""
        if timestamp is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        os.makedirs('metrics', exist_ok=True)
        row = {**metrics, 'variant': self.variant, 'timestamp': timestamp, 'pseudo_normal_used': self.pseudo_normal_used}
        import pandas as pd  # re-imported for locality as in original
        df = pd.DataFrame([row])
        out_file = f'metrics/ugr16_anomaly_metrics_{self.variant}_{timestamp}.csv'
        df.to_csv(out_file, index=False)
        hist_file = 'metrics/ugr16_anomaly_metrics_history.csv'
        if os.path.exists(hist_file):
            prev = pd.read_csv(hist_file)
            df = pd.concat([prev, df], ignore_index=True)
            df.to_csv(hist_file, index=False)
        logger.info(f"Metrics saved: {out_file}; history updated: {hist_file}")


def main():
    """Train and evaluate the UGR16 Isolation Forest anomaly detector (real-time optimized)."""

    parser = argparse.ArgumentParser(description="Train UGR16 Isolation Forest anomaly detector")
    parser.add_argument('--variant', default='v1')
    parser.add_argument('--preprocessed-dir', default=None, help='Directory containing preprocessed train/test CSVs (from data_prep/preprocess_ugr16.py)')
    parser.add_argument('--n_estimators', type=int, default=60)
    parser.add_argument('--contamination', type=float, default=0.05)
    parser.add_argument('--adaptive', action='store_true', default=False)
    parser.add_argument('--adaptive_target_fpr', type=float, default=0.05)
    parser.add_argument('--model_dir', default='models')
    parser.add_argument('--no_eval', action='store_true')
    args = parser.parse_args()

    logger.info("Starting UGR16 anomaly detection training pipeline")
    variant = args.variant

    try:
        detector = UGR16AnomalyDetector(variant=variant)
        if args.preprocessed_dir:
            # Load generic preprocessed format: train.csv/test.csv with a single 'label' column
            import pandas as pd
            train_path = os.path.join(args.preprocessed_dir, 'train.csv')
            test_path = os.path.join(args.preprocessed_dir, 'test.csv')
            if not os.path.exists(train_path):
                raise FileNotFoundError(f"Missing preprocessed train.csv in {args.preprocessed_dir}")
            if not os.path.exists(test_path):
                raise FileNotFoundError(f"Missing preprocessed test.csv in {args.preprocessed_dir}")
            train_df = pd.read_csv(train_path)
            test_df = pd.read_csv(test_path)
            if 'label' not in train_df.columns or 'label' not in test_df.columns:
                raise ValueError("Preprocessed files must include a 'label' column")
            X_train = train_df.drop(columns=['label'])
            Y_train = pd.DataFrame({'attack': train_df['label'].astype(int)})
            X_test = test_df.drop(columns=['label'])
            Y_test = pd.DataFrame({'attack': test_df['label'].astype(int)})
            X_train_normal, X_train_attack, X_test_normal, X_test_attack = detector.preprocess_for_anomaly_detection(
                X_train, Y_train, X_test, Y_test
            )
        else:
            X_train, Y_train, X_test, Y_test = detector.load_ugr16_data()
            X_train_normal, X_train_attack, X_test_normal, X_test_attack = detector.preprocess_for_anomaly_detection(
                X_train, Y_train, X_test, Y_test
            )
        detector.train_anomaly_detector(
            X_train_normal,
            n_estimators=args.n_estimators,
            contamination=args.contamination,
            adaptive=args.adaptive,
            adaptive_target_fpr=args.adaptive_target_fpr,
        )
        if not args.no_eval:
            metrics = detector.evaluate_anomaly_detector(X_test_normal, X_test_attack)
            detector.save_metrics(metrics)

        os.makedirs(args.model_dir, exist_ok=True)
        model_path = os.path.join(args.model_dir, f'ugr16_anomaly_detector_{variant}.joblib')
        detector.save_model(model_path)

        # Save minimal artifact
        import joblib
        joblib.dump(
            detector.minimal_artifact(),
            os.path.join(args.model_dir, f'ugr16_anomaly_detector_{variant}_minimal.joblib'),
            compress=3,
        )
        logger.info(f"UGR16 {variant} anomaly detection completed successfully")
    except Exception as e:
        logger.error(f"Error in UGR16 anomaly detection: {str(e)}")
        raise


if __name__ == "__main__":
    main()