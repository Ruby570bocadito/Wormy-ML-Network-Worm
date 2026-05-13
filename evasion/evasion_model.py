"""Evasion Detection Model — predicts probability of detection for a given action profile."""

import json
import os
from typing import Dict, List, Optional

import numpy as np

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
            except Exception:
                pass
        self.model = self._train_synthetic()

    def _train_synthetic(self):
        if not SKLEARN_AVAILABLE:
            return None
        np.random.seed(42)
        n = 2000
        X = np.random.rand(n, len(FEATURE_NAMES))
        y = np.zeros(n, dtype=int)
        for i in range(n):
            risk = X[i, 5] * 0.3 + X[i, 6] * 0.25 + X[i, 7] * 0.2 + X[i, 9] * 0.15
            noise = np.random.rand() * 0.2
            if risk + noise > 0.7:
                y[i] = 2
            elif risk + noise > 0.4:
                y[i] = 1
        model = GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)
        model.fit(X, y)
        self.is_trained = True
        if self.model_path:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, "wb") as f:
                pickle.dump(model, f)
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
        scan_rate = features.get("scan_rate", 0)
        stealth_delay = features.get("stealth_delay", 1)
        has_edr = features.get("has_edr", 0)
        has_ids = features.get("has_ids", 0)
        is_honeypot = features.get("is_honeypot", 0)
        score = 0.0
        if scan_rate > 100:
            score += 0.3
        if stealth_delay < 0.5:
            score += 0.2
        if has_edr:
            score += 0.25
        if has_ids:
            score += 0.15
        if is_honeypot:
            score += 0.4
        return min(score, 1.0)

    def get_status(self) -> Dict:
        return {
            "trained": self.is_trained,
            "model_path": self.model_path,
            "backend": "sklearn" if self.model and SKLEARN_AVAILABLE else "heuristic",
        }
