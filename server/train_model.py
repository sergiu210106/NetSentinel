"""
Sprint 2 - Task 2.1: Dataset Preparation & Model Training
Downloads the NSL-KDD dataset, trains a Random Forest classifier,
and saves the model to disk as a pickle file.
"""

import os
import pickle
import urllib.request
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

# ── Dataset ────────────────────────────────────────────────────────────────────
# NSL-KDD hosted on GitHub (defcom17/NSL_KDD is the canonical public mirror)
DATASET_URL  = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
DATASET_PATH = "KDDTrain+.txt"
MODEL_PATH   = "model.pkl"

# All 43 columns in the NSL-KDD flat file (41 features + label + difficulty)
ALL_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

# Sprint 2 keeps it simple — only these 4 features are used for training
FEATURES = ["duration", "protocol_type", "src_bytes", "dst_bytes"]

# Protocol encoding must match what ThreatDetector.predict() sends at inference
PROTOCOL_MAP = {"tcp": 0, "udp": 1, "icmp": 2}


def download_dataset():
    if os.path.exists(DATASET_PATH):
        print(f"[*] Dataset already exists at '{DATASET_PATH}', skipping download.")
        return
    print(f"[*] Downloading NSL-KDD dataset from:\n    {DATASET_URL}")
    urllib.request.urlretrieve(DATASET_URL, DATASET_PATH)
    print(f"[+] Saved to '{DATASET_PATH}'")


def load_and_prepare(path: str) -> tuple[pd.DataFrame, pd.Series]:
    """Loads the dataset and returns (X, y) ready for sklearn."""
    df = pd.read_csv(path, header=None, names=ALL_COLUMNS)
    print(f"[*] Loaded {len(df):,} rows from dataset.")

    # ── Feature selection ───────────────────────────────────────────────────
    X = df[FEATURES].copy()

    # Encode protocol_type string → integer (unknown protocols → -1)
    X["protocol_type"] = (
        X["protocol_type"].str.lower().map(PROTOCOL_MAP).fillna(-1).astype(int)
    )

    # ── Label binarisation ──────────────────────────────────────────────────
    # NSL-KDD label "normal" → 0 (Benign), anything else → 1 (Malicious)
    y = (df["label"].str.lower() != "normal").astype(int)

    benign    = (y == 0).sum()
    malicious = (y == 1).sum()
    print(f"[*] Class distribution — Benign: {benign:,}  |  Malicious: {malicious:,}")

    return X, y


def train_and_save(X: pd.DataFrame, y: pd.Series):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"[*] Training Random Forest on {len(X_train):,} samples…")
    clf = RandomForestClassifier(
        n_estimators=100,
        n_jobs=-1,        # use all CPU cores
        random_state=42,
    )
    clf.fit(X_train, y_train)
    print("[+] Training complete.")

    # ── Evaluation ──────────────────────────────────────────────────────────
    y_pred = clf.predict(X_test)
    print("\n── Evaluation on hold-out test set ──────────────────────────────")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    # ── Persist ─────────────────────────────────────────────────────────────
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"[+] Model saved to '{MODEL_PATH}'")


if __name__ == "__main__":
    download_dataset()
    X, y = load_and_prepare(DATASET_PATH)
    train_and_save(X, y)
