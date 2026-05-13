"""Train and persist evasion_model.pkl for detection probability prediction."""

import os
import pickle
import sys

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger

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


def generate_data(n_samples=5000):
    np.random.seed(42)
    X = np.random.rand(n_samples, len(FEATURE_NAMES))
    y = np.zeros(n_samples, dtype=int)

    for i in range(n_samples):
        risk = (
            X[i, 5] * 0.3
            + X[i, 6] * 0.25
            + X[i, 7] * 0.2
            + X[i, 8] * 0.15
            + X[i, 9] * 0.1
            + X[i, 10] * 0.4
            + X[i, 0] * 0.2
            - X[i, 1] * 0.15
        )
        noise = np.random.rand() * 0.2
        if risk + noise > 0.65:
            y[i] = 2
        elif risk + noise > 0.35:
            y[i] = 1

    logger.info(
        f"Generated {n_samples} samples — "
        f"{np.sum(y == 0)} safe, {np.sum(y == 1)} suspicious, {np.sum(y == 2)} detected"
    )
    return X, y


def main():
    save_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml_models", "saved"
    )
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, "evasion_model.pkl")

    X, y = generate_data()
    logger.info("Training GradientBoostingClassifier (n_estimators=150, max_depth=6)...")
    model = GradientBoostingClassifier(n_estimators=150, max_depth=6, random_state=42)
    model.fit(X, y)

    with open(save_path, "wb") as f:
        pickle.dump(model, f)

    logger.success(f"Evasion model saved to {save_path}")
    return save_path


if __name__ == "__main__":
    main()
