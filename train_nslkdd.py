#!/usr/bin/env python3
"""
train_nslkdd.py - trains Model A (RF / DT / KNN) on the NSL-KDD CSV (e.g. kdd_train.csv).
Run:  python3 train_nslkdd.py [path/to/kdd_train.csv]
Classes: normal, dos, probe, r2l, u2r (families). Output: models/nsl/*
"""
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

from config import BASE_DIR, NSL_DIR
from kdd_loader import label_column, read_kdd

FAMILY = {}
for fam, names in {
    "dos": "back land neptune pod smurf teardrop apache2 udpstorm processtable worm mailbomb",
    "probe": "satan ipsweep nmap portsweep mscan saint",
    "r2l": "guess_passwd ftp_write imap phf multihop warezmaster warezclient spy xlock xsnoop "
           "snmpguess snmpgetattack httptunnel sendmail named",
    "u2r": "buffer_overflow loadmodule rootkit perl sqlattack xterm ps",
}.items():
    for n in names.split():
        FAMILY[n] = fam
DROP = {"difficulty", "difficulty_level", "score", "level"}


find_label = label_column


def main(csv_path=None, progress=print):
    merged = os.path.join(BASE_DIR, "data", "kdd_train_plus_live.csv")
    csv_path = csv_path or (merged if os.path.exists(merged) else os.path.join(BASE_DIR, "data", "kdd_train.csv"))
    os.makedirs(NSL_DIR, exist_ok=True)
    progress(f"Loading {csv_path}")
    df = read_kdd(csv_path)
    progress(f'Loaded {len(df)} rows x {df.shape[1]} columns')
    lab = find_label(df)
    raw = df[lab].astype(str).str.lower().str.strip().str.rstrip(".")
    y = raw.map(lambda x: "normal" if x == "normal" else FAMILY.get(x, "other"))
    X = df.drop(columns=[c for c in df.columns if c == lab or c.lower() in DROP])
    counts = y.value_counts()
    rare = counts[counts < 5].index                      # too few samples to stratify
    keep = ~y.isin(rare)
    X, y = X[keep].reset_index(drop=True), y[keep].reset_index(drop=True)

    encoders, defaults, choices = {}, {}, {}
    for c in X.columns:
        if not pd.api.types.is_numeric_dtype(X[c]):
            defaults[c] = X[c].mode()[0]
            enc = LabelEncoder().fit(X[c].astype(str))
            encoders[c] = enc
            choices[c] = sorted(enc.classes_.tolist())
            X[c] = enc.transform(X[c].astype(str))
        else:
            defaults[c] = float(X[c].median())
    order = list(X.columns)
    Xtr, Xte, ytr, yte = train_test_split(X.values, y.values, test_size=0.4, stratify=y.values, random_state=42)
    scaler = StandardScaler().fit(Xtr)
    models = {"rf": RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42),
              "dt": DecisionTreeClassifier(random_state=42),
              "knn": KNeighborsClassifier(n_neighbors=5)}
    metrics = {}
    for n, m in models.items():
        progress(f"Training {n.upper()} ...")
        if n == "knn":
            m.fit(scaler.transform(Xtr), ytr)
            idx = np.random.RandomState(1).choice(len(Xte), min(5000, len(Xte)), replace=False)
            pred, truth = m.predict(scaler.transform(Xte[idx])), yte[idx]   # KNN scored on a 5000-row sample
        else:
            m.fit(Xtr, ytr)
            pred, truth = m.predict(Xte), yte
        metrics[n] = {"accuracy": accuracy_score(truth, pred),
                      "precision": precision_score(truth, pred, average="macro", zero_division=0),
                      "recall": recall_score(truth, pred, average="macro", zero_division=0),
                      "macro_f1": f1_score(truth, pred, average="macro", zero_division=0)}
        joblib.dump(m, os.path.join(NSL_DIR, f"{n}.pkl"))
    joblib.dump(encoders, os.path.join(NSL_DIR, "encoders.pkl"))
    joblib.dump(scaler, os.path.join(NSL_DIR, "scaler.pkl"))
    for name, obj in (("feature_order", order), ("defaults", defaults), ("choices", choices),
                      ("metrics", {"classes": sorted(set(y)), "train_rows": len(Xtr), **metrics})):
        json.dump(obj, open(os.path.join(NSL_DIR, f"{name}.json"), "w"), indent=2)
    progress("Done. " + json.dumps({k: round(v["accuracy"], 4) for k, v in metrics.items()}))
    return metrics


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
