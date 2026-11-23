#!/usr/bin/env python3
"""
train_models.py - trains Model B (Random Forest, Decision Tree, KNN) on data/flows.csv.

Run:  python3 train_models.py
Out:  models/rf.pkl dt.pkl knn.pkl scaler.pkl feature_order.json metrics.json
      models/confusion_<model>.png  models/feature_importance.png

Also exposes make_ml_predict() so detector.decide() can use the trained model.
"""
import json
import os

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score)
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from feature_extractor import FEATURE_NAMES

OUT = "models"


def main():
    os.makedirs(OUT, exist_ok=True)
    df = pd.read_csv("data/flows.csv")
    print(df["label"].value_counts(), "\n")
    X, y = df[FEATURE_NAMES].values, df["label"].values

    # stratified split keeps every class in both sets
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
    scaler = StandardScaler().fit(Xtr)

    models = {
        "rf": RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42),
        "dt": DecisionTreeClassifier(class_weight="balanced", random_state=42),
        "knn": KNeighborsClassifier(n_neighbors=5),
    }
    metrics = {}
    for name, m in models.items():
        if name == "knn":
            m.fit(scaler.transform(Xtr), ytr)
            pred = m.predict(scaler.transform(Xte))
        else:
            m.fit(Xtr, ytr)
            pred = m.predict(Xte)
        metrics[name] = {"accuracy": accuracy_score(yte, pred),
                         "macro_f1": f1_score(yte, pred, average="macro")}
        print(f"=== {name.upper()} ===")
        print(classification_report(yte, pred, zero_division=0))
        labels = sorted(set(y))
        cm = confusion_matrix(yte, pred, labels=labels)
        fig, ax = plt.subplots(figsize=(8, 7))
        ax.imshow(cm, cmap="Blues")
        ax.set_xticks(range(len(labels)), labels, rotation=60, ha="right")
        ax.set_yticks(range(len(labels)), labels)
        for i in range(len(labels)):
            for j in range(len(labels)):
                ax.text(j, i, cm[i, j], ha="center", va="center", fontsize=7)
        ax.set_title(f"Confusion matrix - {name}")
        fig.tight_layout()
        fig.savefig(f"{OUT}/confusion_{name}.png", dpi=120)
        plt.close(fig)
        joblib.dump(m, f"{OUT}/{name}.pkl")

    # feature importance (also feeds the "key drivers" explanation on the UI)
    imp = models["rf"].feature_importances_
    order = np.argsort(imp)[::-1][:15]
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.barh([FEATURE_NAMES[i] for i in order][::-1], imp[order][::-1])
    ax.set_title("Top features (Random Forest)")
    fig.tight_layout()
    fig.savefig(f"{OUT}/feature_importance.png", dpi=120)

    joblib.dump(scaler, f"{OUT}/scaler.pkl")
    json.dump(FEATURE_NAMES, open(f"{OUT}/feature_order.json", "w"))
    json.dump(metrics, open(f"{OUT}/metrics.json", "w"), indent=2)
    base = df[df["label"] == "normal"][FEATURE_NAMES].median().to_dict()
    json.dump(base, open(f"{OUT}/baseline.json", "w"), indent=2)
    print(json.dumps(metrics, indent=2))


def make_ml_predict(model_path=f"{OUT}/rf.pkl"):
    """Returns f(features_dict) -> (label, probability) for detector.decide()."""
    model = joblib.load(model_path)

    def predict(f):
        x = np.array([[f.get(k, 0.0) for k in FEATURE_NAMES]])
        proba = model.predict_proba(x)[0]
        i = int(np.argmax(proba))
        return model.classes_[i], float(proba[i])
    return predict


if __name__ == "__main__":
    main()
