"""Combine the live normal-traffic dataset with the NSL-KDD training file."""
import os

import pandas as pd

from config import DATA_DIR
from flowtracker import NORMAL_CSV
from kdd_loader import KDD_COLUMNS, label_column, read_kdd
from nslkdd_model import ESSENTIAL, _derive

MERGED = os.path.join(DATA_DIR, "kdd_train_plus_live.csv")
KDD = os.path.join(DATA_DIR, "kdd_train.csv")


def live_info():
    n = sum(1 for _ in open(NORMAL_CSV)) - 1 if os.path.exists(NORMAL_CSV) else 0
    return {"normal_connections": max(n, 0), "merged_exists": os.path.exists(MERGED), "kdd_exists": os.path.exists(KDD)}


def merge_live_normal(max_add=20000):
    if not os.path.exists(KDD):
        raise ValueError("upload kdd_train.csv first (Admin > Dataset & Training)")
    if not os.path.exists(NORMAL_CSV):
        raise ValueError("no live normal data yet - start the capture and let some traffic flow")
    base = read_kdd(KDD)
    live = pd.read_csv(NORMAL_CSV)
    if live.empty:
        raise ValueError("normal_connections.csv is empty")
    if len(live) > max_add:
        live = live.sample(max_add, random_state=1)
    lab = label_column(base)
    feats = [c for c in KDD_COLUMNS if c in base.columns]
    defaults = {c: (base[c].median() if pd.api.types.is_numeric_dtype(base[c]) else base[c].mode()[0]) for c in feats}
    rows = []
    for r in live.to_dict("records"):
        row = _derive({k: r[k] for k in ESSENTIAL})         # derived error / rate features
        for c in feats:
            row.setdefault(c, defaults[c])
        row = {c: row[c] for c in feats}
        row[lab] = "normal"
        if "difficulty" in base.columns:
            row["difficulty"] = 21
        rows.append(row)
    add = pd.DataFrame(rows, columns=base.columns)
    out = pd.concat([base, add], ignore_index=True)
    out.to_csv(MERGED, index=False)
    return {"original_rows": len(base), "live_rows_added": len(add), "total_rows": len(out), "file": os.path.basename(MERGED)}
