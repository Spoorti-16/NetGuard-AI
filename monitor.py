"""Background live loop: capture window -> features -> detector -> DB -> optional auto-block."""
import json
import os
import threading
import time
from collections import deque

import db
import response_engine as resp
from config import CAPTURE_DIR, MODEL_DIR, SERVER_IP
from detector import decide
from feature_extractor import FEATURE_NAMES, capture_window, extract_features, read_pcap


class Monitor:
    def __init__(self):
        self.running = False
        self.thread = None
        self.log = deque(maxlen=200)
        self.history = deque(maxlen=60)
        self.latest = None
        self.ml_loaded = False

    def _log(self, msg):
        self.log.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def _load_ml(self):
        p = os.path.join(MODEL_DIR, "rf.pkl")
        if os.path.exists(p):
            from train_models import make_ml_predict
            self.ml_loaded = True
            return make_ml_predict(p)
        self.ml_loaded = False
        return None

    def start(self):
        if self.running:
            return {"error": "already running"}
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return {"ok": "monitoring started"}

    def stop(self):
        self.running = False
        self._log("Stop requested (finishes current window)")
        return {"ok": "stopping"}

    def status(self):
        return {"running": self.running, "ml_loaded": self.ml_loaded, "latest": self.latest,
                "history": list(self.history), "log": list(self.log)[-40:]}

    def _loop(self):
        ml = self._load_ml()
        self._log(f"Monitoring started (Model B {'loaded' if ml else 'NOT trained - rules only'})")
        path = os.path.join(CAPTURE_DIR, "_live.pcap")
        while self.running:
            iface, win = db.get_setting("iface"), int(db.get_setting("window") or 5)
            try:
                if os.path.exists(path):
                    os.remove(path)
                capture_window(iface, win, path)
                if not os.path.exists(path):
                    self._log(f"Capture failed on '{iface}' - run as root, check tshark and interface name")
                    time.sleep(2)
                    continue
                f = extract_features(read_pcap(path), win, exclude=(SERVER_IP,))
                v = decide(f, ml)
                self._store(f, v)
                resp.expire_blocks()
            except FileNotFoundError:
                self._log("tshark not found. Install: sudo apt install tshark")
                self.running = False
            except Exception as e:      # keep the loop alive
                self._log(f"Error: {e}")
                time.sleep(2)
        self._log("Monitoring stopped")

    def _store(self, f, v):
        feats = {k: f.get(k, 0) for k in FEATURE_NAMES}
        pt = {"ts": db.now(), "pps": round(f["pkts_per_sec"], 1), "syn": round(f["syn_rate"], 1),
              "category": v["category"], "label": v["label"]}
        self.history.append(pt)
        self.latest = {**v, "features": {**feats, "top_talker": f.get("top_talker")}, "ts": pt["ts"]}
        db.ex("INSERT INTO windows(ts,pkts_per_sec,syn_rate,bytes_per_sec,category,label) VALUES(?,?,?,?,?,?)",
              (pt["ts"], f["pkts_per_sec"], f["syn_rate"], f["bytes_per_sec"], v["category"], v["label"]))
        if v["category"] == "normal":
            self._log(f"normal  {pt['pps']} pkts/s")
            return
        did = db.add_detection("live", v["category"], v["label"], v["confidence"], v["threat_score"],
                               v["severity"], v.get("source_ip"), v["evidence"], v["cause"], v["fix"],
                               v.get("agreement"), "ModelB+rules" if self.ml_loaded else "rules",
                               json.dumps(feats))
        self.latest["detection_id"] = did
        self._log(f"{v['category'].upper()} {v['label']} score={v['threat_score']} {v['evidence']}")
        if (v["category"] == "attack" and db.get_setting("auto_block") == "1" and v.get("source_ip")
                and v["confidence"] >= float(db.get_setting("block_conf")) and not v.get("needs_review")):
            r = resp.block(v["source_ip"], f"auto: {v['label']}", v["label"])
            self._log(f"AUTO-BLOCK {v['source_ip']}: {r.get('ok') or r.get('error')}")


monitor = Monitor()
