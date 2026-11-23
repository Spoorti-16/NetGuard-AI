"""Model A runtime: manual 12-field prediction + CSV batch prediction (NSL-KDD)."""
import json
import os

import joblib
import numpy as np
import pandas as pd

from config import NSL_DIR

ESSENTIAL = ["src_bytes", "dst_bytes", "flag", "protocol_type", "service", "count", "same_srv_rate",
             "diff_srv_rate", "dst_host_srv_count", "duration", "logged_in", "is_guest_login"]
NUMERIC_RANGE = {"src_bytes": (0, 1e9), "dst_bytes": (0, 1e9), "count": (0, 511), "same_srv_rate": (0, 1),
                 "diff_srv_rate": (0, 1), "dst_host_srv_count": (0, 255), "duration": (0, 1e7),
                 "logged_in": (0, 1), "is_guest_login": (0, 1)}
# Real rows taken from the NSL-KDD training file (chosen for confident 12-field predictions)
PRESETS = {
    "Normal Web Traffic": {
        "src_bytes": 262,
        "dst_bytes": 5480,
        "flag": "SF",
        "protocol_type": "tcp",
        "service": "http",
        "count": 1,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_srv_count": 255,
        "duration": 0,
        "logged_in": 1,
        "is_guest_login": 0
    },
    "DoS Neptune (SYN Flood)": {
        "src_bytes": 0,
        "dst_bytes": 0,
        "flag": "S0",
        "protocol_type": "tcp",
        "service": "Z39_50",
        "count": 273,
        "same_srv_rate": 0.08,
        "diff_srv_rate": 0.05,
        "dst_host_srv_count": 23,
        "duration": 0,
        "logged_in": 0,
        "is_guest_login": 0
    },
    "DoS Smurf (ICMP Flood)": {
        "src_bytes": 1032,
        "dst_bytes": 0,
        "flag": "SF",
        "protocol_type": "icmp",
        "service": "ecr_i",
        "count": 508,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_srv_count": 81,
        "duration": 0,
        "logged_in": 0,
        "is_guest_login": 0
    },
    "Probe PortSweep": {
        "src_bytes": 0,
        "dst_bytes": 0,
        "flag": "REJ",
        "protocol_type": "tcp",
        "service": "private",
        "count": 420,
        "same_srv_rate": 0.0,
        "diff_srv_rate": 0.52,
        "dst_host_srv_count": 1,
        "duration": 0,
        "logged_in": 0,
        "is_guest_login": 0
    },
    "Probe Satan": {
        "src_bytes": 0,
        "dst_bytes": 0,
        "flag": "REJ",
        "protocol_type": "tcp",
        "service": "aol",
        "count": 511,
        "same_srv_rate": 0.0,
        "diff_srv_rate": 1.0,
        "dst_host_srv_count": 1,
        "duration": 0,
        "logged_in": 0,
        "is_guest_login": 0
    },
    "DoS Teardrop (UDP)": {
        "src_bytes": 28,
        "dst_bytes": 0,
        "flag": "SF",
        "protocol_type": "udp",
        "service": "private",
        "count": 70,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_srv_count": 70,
        "duration": 0,
        "logged_in": 0,
        "is_guest_login": 0
    }
}
REMEDIATION = {
    "dos": ["iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 5 -j ACCEPT",
            "iptables -A INPUT -p tcp --syn -j DROP"],
    "probe": ["iptables -A INPUT -p tcp --syn -m hashlimit --hashlimit-above 10/sec "
              "--hashlimit-mode srcip --hashlimit-name probe -j DROP"],
    "r2l": ["iptables -A INPUT -p tcp -m multiport --dports 21,22,23 -m recent --name bf --set",
            "iptables -A INPUT -p tcp -m multiport --dports 21,22,23 -m recent --name bf --update --seconds 60 --hitcount 5 -j DROP"],
    "u2r": ["# Isolate the host, disable guest logins, audit privileged accounts"],
    "normal": ["iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT"],
}
_cache = {}


def available():
    return os.path.exists(os.path.join(NSL_DIR, "rf.pkl")) and os.path.exists(os.path.join(NSL_DIR, "feature_order.json"))


def reset_cache():
    _cache.clear()


def _load():
    if not _cache:
        j = lambda n: json.load(open(os.path.join(NSL_DIR, n)))
        _cache.update(order=j("feature_order.json"), defaults=j("defaults.json"), choices=j("choices.json"),
                      enc=joblib.load(os.path.join(NSL_DIR, "encoders.pkl")),
                      scaler=joblib.load(os.path.join(NSL_DIR, "scaler.pkl")), models={})
    return _cache


def choices():
    return _load()["choices"] if available() else {"flag": ["SF", "S0", "REJ"], "protocol_type": ["tcp", "udp", "icmp"], "service": ["http", "private"]}


def _model(name):
    c = _load()
    if name not in ("rf", "dt", "knn"):
        raise ValueError("unknown model")
    if name not in c["models"]:
        c["models"][name] = joblib.load(os.path.join(NSL_DIR, f"{name}.pkl"))
    return c["models"][name]


def _encode(col, val, c):
    enc = c["enc"][col]
    s = str(val)
    if s not in enc.classes_:
        s = str(c["defaults"][col])
    return float(enc.transform([s])[0])


def _derive(row):
    """Fill missing NSL-KDD features that follow directly from the 12 inputs
    (S0 -> SYN-error rates ~1, REJ -> reject rates ~1, same/diff rates copy across)."""
    r = dict(row)
    flag = str(r.get("flag", ""))
    serr = 1.0 if flag in ("S0", "S1", "S2", "S3") else 0.0
    rerr = 1.0 if flag == "REJ" else 0.0
    count, same, diff = float(r.get("count", 0)), float(r.get("same_srv_rate", 0)), float(r.get("diff_srv_rate", 0))
    for k, v in {"serror_rate": serr, "srv_serror_rate": serr, "dst_host_serror_rate": serr,
                 "dst_host_srv_serror_rate": serr, "rerror_rate": rerr, "srv_rerror_rate": rerr,
                 "dst_host_rerror_rate": rerr, "dst_host_srv_rerror_rate": rerr,
                 "srv_count": count * same, "dst_host_same_srv_rate": same,
                 "dst_host_diff_srv_rate": diff}.items():
        r.setdefault(k, v)
    return r


def _vector(row, c):
    row = _derive(row)
    out = []
    for col in c["order"]:
        v = row.get(col, c["defaults"][col])
        if pd.isna(v):
            v = c["defaults"][col]
        out.append(_encode(col, v, c) if col in c["enc"] else float(v))
    return out


def _proba(name, X):
    c = _load()
    m = _model(name)
    X = np.array(X, dtype=float)
    return m.classes_, m.predict_proba(c["scaler"].transform(X) if name == "knn" else X)


def severity(score):
    return "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"


def validate(form):
    clean, ch = {}, choices()
    for k in ESSENTIAL:
        if k not in form or str(form[k]).strip() == "":
            raise ValueError(f"{k} is required")
        if k in NUMERIC_RANGE:
            try:
                v = float(form[k])
            except ValueError:
                raise ValueError(f"{k} must be a number")
            lo, hi = NUMERIC_RANGE[k]
            if not lo <= v <= hi:
                raise ValueError(f"{k} must be between {lo:g} and {hi:g}")
            clean[k] = v
        else:
            if str(form[k]) not in ch.get(k, [str(form[k])]):
                raise ValueError(f"{k}: invalid choice '{form[k]}'")
            clean[k] = str(form[k])
    return clean


def predict_manual(model, form):
    c = _load()
    clean = validate(form)
    classes, proba = _proba(model, [_vector(clean, c)])
    p = proba[0]
    i = int(np.argmax(p))
    label = str(classes[i])
    p_norm = float(p[list(classes).index("normal")]) if "normal" in classes else 0.0
    mal = 1 - p_norm
    score = round(mal * 100, 2)
    drivers = []
    for k in ESSENTIAL:
        base, obs = c["defaults"][k], clean[k]
        if k in NUMERIC_RANGE:
            dev = abs(obs - float(base)) / (abs(float(base)) + 1)
        else:
            dev = 0 if obs == base else 1
        drivers.append({"feature": k, "observed": obs, "baseline": base, "deviation": round(float(dev), 2)})
    drivers = sorted(drivers, key=lambda d: -d["deviation"])[:4]
    return {"label": label, "category": "normal" if label == "normal" else "attack",
            "confidence": round(float(p[i]), 4), "p_normal": round(p_norm, 4), "p_malicious": round(mal, 4),
            "threat_score": score, "severity": severity(score) if label != "normal" else "LOW",
            "remediation": REMEDIATION.get(label, ["# Log and review"]), "drivers": drivers, "model": model}


def predict_dataframe(model, df, limit=5000):
    c = _load()
    df = df.head(limit)
    X = [_vector(r, c) for r in df.to_dict("records")]
    classes, proba = _proba(model, X)
    out = []
    for r, p in zip(df.to_dict("records"), proba):
        i = int(np.argmax(p))
        label = str(classes[i])
        out.append({"label": label, "category": "normal" if label == "normal" else "attack",
                    "confidence": round(float(p[i]), 4), "duration": r.get("duration", ""),
                    "src_bytes": r.get("src_bytes", ""), "dst_bytes": r.get("dst_bytes", "")})
    return out
