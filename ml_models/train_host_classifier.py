"""Train and persist host_classifier.pkl with enriched synthetic data."""

import os
import pickle
import sys

import numpy as np
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger

FEATURE_NAMES = [
    "port_21",
    "port_22",
    "port_23",
    "port_25",
    "port_53",
    "port_80",
    "port_110",
    "port_135",
    "port_139",
    "port_143",
    "port_443",
    "port_445",
    "port_993",
    "port_995",
    "port_1433",
    "port_3306",
    "port_3389",
    "port_5432",
    "port_5900",
    "port_6379",
    "port_8080",
    "port_8443",
    "port_9200",
    "port_27017",
    "total_ports",
    "has_windows_ports",
    "has_linux_ports",
    "has_db_ports",
    "has_web_ports",
    "banner_count",
    "has_ssh_banner",
    "has_smb_banner",
    "has_http_banner",
]
OS_LABELS = [
    "workstation",
    "server",
    "database",
    "web_server",
    "domain_controller",
    "network_device",
    "iot",
]

N_SAMPLES = 5000


def generate_synthetic_data(n_samples=N_SAMPLES):
    np.random.seed(42)
    n_features = len(FEATURE_NAMES)
    X = np.random.randint(0, 2, size=(n_samples, n_features)).astype(float)
    y = np.zeros(n_samples, dtype=int)

    for i in range(n_samples):
        ports_active = np.where(X[i, :24] == 1)[0]

        if 17 in ports_active and 7 in ports_active:
            y[i] = 4
            X[i, 17] = 1
            X[i, 26] = 1
        elif 15 in ports_active or 16 in ports_active:
            if 15 in ports_active:
                y[i] = 2
                X[i, 27] = 1
            else:
                y[i] = 0
        elif 5 in ports_active or 10 in ports_active or 20 in ports_active:
            y[i] = 3
            X[i, 28] = 1
            X[i, 31] = 1
        elif 1 in ports_active:
            y[i] = 1
            X[i, 26] = 0
            X[i, 25] = 1
            X[i, 29] = 1
        elif 2 in ports_active:
            y[i] = 5
        elif 22 in ports_active or 23 in ports_active:
            y[i] = 2
            X[i, 27] = 1
        else:
            y[i] = 6

        X[i, 24] = len(ports_active)
        X[i, 25] = int(any(p in ports_active for p in [1, 24, 25]))
        X[i, 26] = int(any(p in ports_active for p in [7, 8, 11, 16]))
        X[i, 27] = int(any(p in ports_active for p in [14, 15, 17, 23]))
        X[i, 28] = int(any(p in ports_active for p in [5, 10, 20, 21]))

    return X, y


def main():
    save_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml_models", "saved"
    )
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, "host_classifier.pkl")

    logger.info(f"Generating {N_SAMPLES} synthetic training samples...")
    X, y = generate_synthetic_data()

    logger.info("Training RandomForest classifier (n_estimators=200, max_depth=12)...")
    model = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
    model.fit(X, y)

    with open(save_path, "wb") as f:
        pickle.dump(model, f)

    logger.success(f"Model saved to {save_path}")
    logger.info(f"  Classes: {OS_LABELS}")
    logger.info(f"  Feature count: {len(FEATURE_NAMES)}")
    logger.info(f"  Samples: {N_SAMPLES}")

    return save_path


if __name__ == "__main__":
    main()
