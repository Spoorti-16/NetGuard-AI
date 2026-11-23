"""scheduler.py - every packet addressed to the admin's own host is queued here and classified in the
order the chosen algorithm picks, so two or more requests arriving at once are handled one at a time
and the admin can watch a live 'response window' of verdicts (normal / fault / attack / unknown).

Algorithms:
  fcfs         - first come, first served
  round_robin  - cycle fairly between the distinct sources that currently have pending requests
  priority     - a source already flagged as an attacker elsewhere in the network jumps the queue
"""
import threading
import time
from collections import deque

import db
from detector import decide
from feature_extractor import extract_features

ALGOS = ("fcfs", "round_robin", "priority")


class Scheduler:
    def __init__(self, maxlen=300):
        self.q = []                      # pending request dicts, small list (fast enough for this volume)
        self._rr_order = []              # round-robin rotation of source IPs
        self.responses = deque(maxlen=maxlen)
        self.lock = threading.Lock()
        self.running = False
        self.admin_ip = None
        self.ml = None
        self._id = 0
        self._recent_src = deque(maxlen=400)   # (ts, src_ip) de-duplication so one burst = one queue entry

    def set_admin_ip(self, ip):
        self.admin_ip = ip

    def set_ml(self, predict_fn):
        self.ml = predict_fn

    def enqueue(self, src_name, src_ip, proto, note=""):
        now = time.time()
        with self.lock:
            # de-duplicate: the same source within 1.5s is one "request", not one per packet
            if any(s == src_ip and now - t < 1.5 for t, s in self._recent_src):
                return None
            self._recent_src.append((now, src_ip))
            self._id += 1
            item = {"id": self._id, "ts": now, "src": src_name, "src_ip": src_ip, "proto": proto, "note": note}
            self.q.append(item)
        return item["id"]

    def _pick(self, algo):
        with self.lock:
            if not self.q:
                return None
            if algo == "priority":
                import netmonitor
                tr = netmonitor.netmon.tracker
                sus = set(tr.suspects) if tr else set()
                i = max(range(len(self.q)), key=lambda k: (self.q[k]["src_ip"] in sus, -self.q[k]["ts"]))
                return self.q.pop(i)
            if algo == "round_robin":
                srcs = []
                for it in self.q:
                    if it["src_ip"] not in srcs:
                        srcs.append(it["src_ip"])
                self._rr_order = [s for s in self._rr_order if s in srcs] + [s for s in srcs if s not in self._rr_order]
                if not self._rr_order:
                    return None
                target = self._rr_order.pop(0)
                self._rr_order.append(target)
                for k, it in enumerate(self.q):
                    if it["src_ip"] == target:
                        return self.q.pop(k)
                return None
            return self.q.pop(0)         # fcfs

    def start(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            algo = db.get_setting("sched_algo") or "fcfs"
            item = self._pick(algo)
            if not item:
                time.sleep(0.4)
                continue
            wait_ms = round((time.time() - item["ts"]) * 1000)
            verdict = self._classify(item)
            row = {**item, "algo": algo, "wait_ms": wait_ms, **verdict}
            self.responses.appendleft(row)
            db.ex("""INSERT INTO queue_log(ts,src,src_ip,algo,wait_ms,category,label,confidence)
                     VALUES(?,?,?,?,?,?,?,?)""",
                  (db.now(), item["src"], item["src_ip"], algo, wait_ms, verdict["category"],
                   verdict["label"], verdict.get("confidence", 0)))
            time.sleep(0.1)

    def _classify(self, item):
        try:
            import netmonitor
            sn = netmonitor.netmon.sniffer
            if not sn:
                return {"category": "unknown", "label": "no-capture", "confidence": 0.0, "evidence": "capture is not running"}
            pk = sn.since(0, 2000, host=item["src_ip"])
            if not pk:
                return {"category": "unknown", "label": "no-data", "confidence": 0.0, "evidence": "no recent packets from this source"}
            rows = [sn.to_row(p) for p in pk if p["proto"] != "ARP"]
            if not rows:
                return {"category": "unknown", "label": "no-data", "confidence": 0.0, "evidence": "only ARP traffic seen"}
            f = extract_features(rows, 5, exclude=(self.admin_ip or "",))
            v = decide(f, self.ml)
            return {"category": v["category"], "label": v["label"], "confidence": v["confidence"], "evidence": v["evidence"]}
        except Exception as e:
            return {"category": "unknown", "label": "error", "confidence": 0.0, "evidence": str(e)}

    def status(self):
        return {"running": self.running, "algo": db.get_setting("sched_algo") or "fcfs",
                "pending": len(self.q), "admin_ip": self.admin_ip, "ml": bool(self.ml),
                "responses": list(self.responses)[:50]}


scheduler = Scheduler()
