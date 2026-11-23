"""netmonitor.py - ties together: sniffer -> flow tracker -> window analysis -> detections -> datasets."""
import csv
import os
import threading
import time
from collections import Counter, defaultdict, deque

import db
import response_engine as resp
from config import DATA_DIR, MODEL_DIR
from detector import FAULTS, decide
from feature_extractor import FEATURE_NAMES, extract_features
from flowtracker import FlowTracker
from netplan import build_plan
from scheduler import scheduler
from sniffer import Sniffer

FLOWS_CSV = os.path.join(DATA_DIR, "flows.csv")
REASON_TO_LABEL = [("refused", "conn_refused"), ("no reply to SYN", "conn_timeout"), ("without reply", "conn_timeout"),
                   ("NXDOMAIN", "dns_nxdomain"), ("without answer", "dns_down"), ("404", "http_404"), ("5", "http_5xx"),
                   ("retransmission", "high_latency_loss"), ("reset", "conn_reset")]
MIN_PKTS = 3             # low threshold so no small flood or stealthy attack ever misses


def reason_label(reason):
    for key, lab in REASON_TO_LABEL:
        if key in reason:
            return lab
    return "fault"


class NetMonitor:
    def __init__(self):
        self.plan = self.sniffer = self.tracker = self.ml = None
        self.running = False
        self.alerts = deque(maxlen=100)
        self.targets = {}
        self.windows_saved = 0
        self.pps = 0.0
        self.error = ""
        self.warnings = []
        self._normal_hits = Counter()
        self._last_id = 0
        self._det_seen = {}

    # ---------------------------------------------------------------- control
    def start(self):
        if self.running:
            return {"error": "already running"}
        try:
            self.plan = build_plan()
        except Exception as e:
            return {"error": f"network_config.json problem: {e}"}
        sn = Sniffer(self.plan["sniff"], self.plan["ip_map"])
        sn.payload_preview = db.get_setting("payload_preview") == "1"
        self.tracker = FlowTracker(max_rows=int(db.get_setting("normal_max") or 50000))
        sn.listeners.append(self.tracker.add)
        sn.listeners.append(self._maybe_enqueue)
        try:
            sn.start()
        except RuntimeError as e:
            return {"error": str(e)}
        self.sniffer, self.warnings, self._last_id = sn, sn.errors[:6], 0
        p = os.path.join(MODEL_DIR, "rf.pkl")
        if os.path.exists(p):
            from train_models import make_ml_predict
            self.ml = make_ml_predict(p)
        else:
            self.ml = None
        scheduler.set_admin_ip(self.plan.get("admin_ip"))
        scheduler.set_ml(self.ml)
        scheduler.start()
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        return {"ok": f"capturing on {len(sn.socks)} of {len(self.plan['sniff'])} ports", "warnings": self.warnings}

    def stop(self):
        self.running = False
        scheduler.stop()
        if self.sniffer:
            self.sniffer.stop()
        return {"ok": "capture stopped"}

    def _maybe_enqueue(self, p, payload=b""):
        """Any 'start of a conversation' packet addressed to the admin's own host joins the scheduler's queue."""
        admin_ip = scheduler.admin_ip
        if not admin_ip or p.get("dst_ip") != admin_ip:
            return
        is_new = ((p["proto"] == "ICMP" and p.get("icmp_type") == 8) or
                  (p["proto"] == "TCP" and p.get("tcp_flags", 0) & 0x02) or
                  p["proto"] in ("UDP", "DNS"))
        if is_new:
            scheduler.enqueue(p["src"], p["src_ip"], p["proto"])

    def set_payload_preview(self, on):
        db.set_setting("payload_preview", "1" if on else "0")
        if self.sniffer:
            self.sniffer.payload_preview = bool(on)

    # ---------------------------------------------------------------- loop
    def _loop(self):
        win, nxt, nxt_train = 5, time.time() + 5, time.time() + 60
        while self.running:
            time.sleep(1)
            try:
                self._flows()
                if time.time() >= nxt:
                    self._analyze(win)
                    nxt += win
                if time.time() >= nxt_train:
                    import auto_train
                    auto_train.maybe_retrain()
                    nxt_train += 60
            except Exception as e:
                self.error = f"{type(e).__name__}: {e}"

    def _flows(self):
        for kind, e in self.tracker.sweep():
            if kind == "normal":
                self._normal_hits[e["src_ip"]] += 1
                self._normal_hits[e["dst_ip"]] += 1
            else:
                lab = reason_label(e["reason"])
                cause, fix = (FAULTS[lab][1], FAULTS[lab][2]) if lab in FAULTS else ("Transfer did not complete", "Check the path and the destination service")
                db.add_detection("flow", "fault", lab, 0.8, 20, "MEDIUM", e["src_ip"], f"{e['src']} -> {e['dst']}: {e['reason']}",
                                 cause, fix, model="flow-tracker")
                self.alerts.appendleft({"ts": e["ts"], "kind": "fault", "label": lab, "src": e["src"], "dst": e["dst"], "detail": e["reason"]})

    def _analyze(self, win):
        pk = self.sniffer.since(self._last_id, limit=20000)
        if not pk:
            self.pps = 0
            return
        self._last_id = pk[-1]["id"]
        self.pps = round(len(pk) / win, 1)
        groups = defaultdict(list)
        for p in pk:
            if p["proto"] == "ARP":
                continue
            row = Sniffer.to_row(p)
            groups[p["src_ip"]].append(row)
            if p["dst_ip"] != p["src_ip"]:
                groups[p["dst_ip"]].append(row)
        verdicts, attack_seen = [], False
        ml_conf = db.get_setting("block_conf")
        for ip, rows in groups.items():
            if len(rows) < MIN_PKTS:
                continue
            f = extract_features(rows, win, exclude=(ip,))
            v = decide(f, self.ml)
            verdicts.append((ip, rows, f, v))
            if v["category"] == "attack":
                attack_seen = True
                src = v.get("source_ip")
                if src:
                    self.tracker.mark_suspect(src)
                self.targets[ip] = {"category": "attack", "label": v["label"], "src": src, "ts": time.time()}
                names = self.sniffer.name
                db.add_detection("network", "attack", v["label"], v["confidence"], v["threat_score"], v["severity"], src,
                                 f"target {names(ip)} ({ip}): {v['evidence']}", v["cause"], v["fix"], v.get("agreement"),
                                 "ModelB+rules" if self.ml else "rules")
                self.alerts.appendleft({"ts": time.strftime("%H:%M:%S"), "kind": "attack", "label": v["label"], "src": names(src) if src else "?",
                                        "dst": names(ip), "detail": f"{v['evidence']} (score {v['threat_score']})"})
                if (db.get_setting("auto_block") == "1" and src and v["confidence"] >= float(ml_conf) and not v.get("needs_review")):
                    r = resp.block(src, f"auto: {v['label']}", v["label"])
                    self.alerts.appendleft({"ts": time.strftime("%H:%M:%S"), "kind": "block", "label": "auto-block", "src": names(src),
                                            "dst": "", "detail": r.get("ok") or r.get("error")})
            elif v["category"] == "fault":
                key = (ip, v["label"])
                if time.time() - self._det_seen.get(key, 0) > 30:
                    self._det_seen[key] = time.time()
                    self.targets[ip] = {"category": "fault", "label": v["label"], "src": None, "ts": time.time()}
                    db.add_detection("network", "fault", v["label"], v["confidence"], v["threat_score"], v["severity"], v.get("source_ip"),
                                     f"target {self.sniffer.name(ip)}: {v['evidence']}", v["cause"], v["fix"], model="rules")
        total = len(pk)
        cat = "attack" if attack_seen else "normal"
        db.ex("INSERT INTO windows(ts,pkts_per_sec,syn_rate,bytes_per_sec,category,label) VALUES(?,?,?,?,?,?)",
              (db.now(), total / win, sum(1 for p in pk if p.get("tcp_flags", 0) & 0x12 == 0x02) / win,
               sum(p["length"] for p in pk) / win, cat, cat))
        # --- normal window rows for the Model B training set (only when nothing suspicious happened)
        if not attack_seen:
            saved = 0
            for ip, rows, f, v in verdicts:
                if v["category"] == "normal" and self._normal_hits.get(ip) and saved < 3:
                    self._save_window(f)
                    saved += 1
        self._normal_hits.clear()

    def _save_window(self, f):
        cols = FEATURE_NAMES + ["label"]
        new = not os.path.exists(FLOWS_CSV)
        if not new:
            with open(FLOWS_CSV) as fh:
                if next(csv.reader(fh), []) != cols:
                    return                                  # different layout: never corrupt the user's file
        with open(FLOWS_CSV, "a", newline="") as fh:
            w = csv.writer(fh)
            if new:
                w.writerow(cols)
            w.writerow([f.get(k, 0.0) for k in FEATURE_NAMES] + ["normal"])
        self.windows_saved += 1

    # ---------------------------------------------------------------- status
    def status(self):
        now = time.time()
        sn, tr = self.sniffer, self.tracker
        return {"running": self.running, "ports": len(sn.socks) if sn else 0, "warnings": self.warnings, "error": self.error,
                "pps": self.pps, "packets": sn.counter if sn else 0, "ml": bool(self.ml),
                "payload_preview": bool(sn.payload_preview) if sn else db.get_setting("payload_preview") == "1",
                "normal_saved": tr.counts["normal_saved"] if tr else 0, "normal_rows": tr.rows_in_file if tr else 0,
                "faulty_flows": tr.counts["faulty"] if tr else 0, "windows_saved": self.windows_saved,
                "traffic_saved": tr.counts["traffic_saved"] if tr else 0, "traffic_rows": tr.traffic_rows_in_file if tr else 0,
                "admin_ip": self.plan.get("admin_ip") if self.plan else None,
                "alerts": list(self.alerts)[:25],
                "targets": {ip: t for ip, t in self.targets.items() if now - t["ts"] < 25}}


netmon = NetMonitor()
