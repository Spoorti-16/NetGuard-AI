"""auto_train.py - retrains Model A and/or Model B automatically once enough new rows have
accumulated in the live datasets. Off by default (Admin > Settings > auto_train); call
maybe_retrain() after an injection finishes, or periodically from the network monitor loop."""
import os
import threading

import db
from config import BASE_DIR, DATA_DIR

_lock = threading.Lock()
_running = {"a": False, "b": False}


def _rows(path):
    if not os.path.exists(path):
        return 0
    with open(path) as fh:
        return max(sum(1 for _ in fh) - 1, 0)


def maybe_retrain():
    if db.get_setting("auto_train") != "1":
        return {"skipped": "auto_train is off (Admin > Settings)"}
    every = int(db.get_setting("retrain_every") or 40)
    out = {}

    n_norm = _rows(os.path.join(DATA_DIR, "normal_connections.csv"))
    last_norm = int(db.get_setting("last_train_rows_normal") or 0)
    if n_norm - last_norm >= every and os.path.exists(os.path.join(DATA_DIR, "kdd_train.csv")):
        out["model_a"] = _retrain_a()
        db.set_setting("last_train_rows_normal", n_norm)

    n_flow = _rows(os.path.join(DATA_DIR, "flows.csv"))
    last_flow = int(db.get_setting("last_train_rows_flows") or 0)
    if n_flow - last_flow >= every:
        out["model_b"] = _retrain_b()
        db.set_setting("last_train_rows_flows", n_flow)

    return out or {"skipped": f"fewer than {every} new rows since the last automatic retrain"}


def _retrain_a():
    with _lock:
        if _running["a"]:
            return "already running"
        _running["a"] = True

    def run():
        try:
            import datasets
            import nslkdd_model
            import train_nslkdd
            datasets.merge_live_normal()
            train_nslkdd.main(csv_path=datasets.MERGED)
            nslkdd_model.reset_cache()
            db.set_setting("last_autotrain_a", db.now())
            db.set_setting("last_autotrain_a_error", "")
        except Exception as e:
            db.set_setting("last_autotrain_a_error", str(e))
        finally:
            _running["a"] = False

    threading.Thread(target=run, daemon=True).start()
    return "started"


def _retrain_b():
    with _lock:
        if _running["b"]:
            return "already running"
        _running["b"] = True

    def run():
        try:
            import train_models
            train_models.main()
            db.set_setting("last_autotrain_b", db.now())
            db.set_setting("last_autotrain_b_error", "")
        except Exception as e:
            db.set_setting("last_autotrain_b_error", str(e))
        finally:
            _running["b"] = False

    threading.Thread(target=run, daemon=True).start()
    return "started"


def status():
    return {"auto_train": db.get_setting("auto_train") == "1", "retrain_every": db.get_setting("retrain_every"),
            "running_a": _running["a"], "running_b": _running["b"],
            "last_autotrain_a": db.get_setting("last_autotrain_a"), "last_autotrain_b": db.get_setting("last_autotrain_b"),
            "last_autotrain_a_error": db.get_setting("last_autotrain_a_error"),
            "last_autotrain_b_error": db.get_setting("last_autotrain_b_error"),
            "rows_normal": _rows(os.path.join(DATA_DIR, "normal_connections.csv")),
            "rows_flows": _rows(os.path.join(DATA_DIR, "flows.csv"))}
