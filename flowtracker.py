"""flowtracker.py - follows every conversation (flow) and decides: completed normally, or faulty?

A flow that completes WITHOUT fault is stored in data/normal_connections.csv (NSL-KDD-style connection records).
Faulty flows (refused, reset, no reply, NXDOMAIN, HTTP 404/5xx, heavy retransmission) are NOT added to the normal set;
they are reported as faults with a reason instead. Flows from a source currently flagged as an attacker are skipped.
"""
import csv
import os
import threading
import time
from collections import defaultdict, deque

from config import DATA_DIR

NORMAL_CSV = os.path.join(DATA_DIR, "normal_connections.csv")
TRAFFIC_CSV = os.path.join(DATA_DIR, "traffic_dataset.csv")
COLUMNS = ["ts", "src_name", "dst_name", "src_ip", "dst_ip", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
           "duration", "count", "same_srv_rate", "diff_srv_rate", "dst_host_srv_count", "logged_in", "is_guest_login",
           "label", "approx_fields"]
TRAFFIC_COLUMNS = COLUMNS + ["concurrent_sources", "underlying_verdict"]
TCP_SERVICES = {80: "http", 8080: "http", 443: "http_443", 22: "ssh", 21: "ftp", 20: "ftp_data", 25: "smtp", 23: "telnet",
                110: "pop_3", 143: "imap4", 53: "domain"}
UDP_SERVICES = {53: "domain_u", 123: "ntp_u", 69: "tftp_u"}


class Flow:
    __slots__ = ("proto", "init_ip", "init_port", "resp_ip", "resp_port", "t0", "t1", "fwd", "bwd", "fbytes", "bbytes",
                 "syn", "synack", "ack_f", "fin_f", "fin_b", "rst", "retrans", "seen", "dns_q", "dns_r", "rcode",
                 "icmp_req", "icmp_rep", "http", "closed_at", "init_name", "resp_name")

    def __init__(self, p):
        self.proto = "UDP" if p["proto"] == "DNS" else p["proto"]
        self.init_ip, self.init_port = p["src_ip"], p["sport"]
        self.resp_ip, self.resp_port = p["dst_ip"], p["dport"]
        self.init_name, self.resp_name = p["src"], p["dst"]
        self.t0 = self.t1 = p["ts"]
        self.fwd = self.bwd = self.fbytes = self.bbytes = 0
        self.syn = self.synack = self.ack_f = self.fin_f = self.fin_b = self.rst = self.retrans = 0
        self.seen = (set(), set())
        self.dns_q = self.dns_r = self.icmp_req = self.icmp_rep = 0
        self.rcode = None
        self.http = 0
        self.closed_at = None


class FlowTracker:
    def __init__(self, idle=8.0, max_rows=50000, contention_window=1.5):
        self.flows = {}
        self.idle = idle
        self.max_rows = max_rows
        self.contention_window = contention_window     # seconds: how close two sources' requests must be to "collide"
        self.suspects = {}                        # ip -> time flagged as attacker
        self.recent = defaultdict(lambda: deque(maxlen=100))      # dst_ip -> (t, service)  (for same/diff-service rate)
        self.dst_arrivals = defaultdict(lambda: deque(maxlen=60))  # dst_ip -> (t, src_ip)  (for contention detection)
        self.faults = deque(maxlen=200)
        self.counts = {"normal_saved": 0, "faulty": 0, "skipped": 0, "traffic_saved": 0}
        self.lock = threading.Lock()
        self._fault_seen = {}
        self.rows_in_file = self._count_rows(NORMAL_CSV)
        self.traffic_rows_in_file = self._count_rows(TRAFFIC_CSV)

    # ----------------------------------------------------------------- ingest
    @staticmethod
    def _key(p):
        if p["proto"] == "ICMP":
            return ("ICMP", tuple(sorted((p["src_ip"], p["dst_ip"]))))
        a, b = (p["src_ip"], p["sport"]), (p["dst_ip"], p["dport"])
        return (p["proto"] if p["proto"] != "DNS" else "UDP", tuple(sorted((a, b))))

    def mark_suspect(self, ip):
        self.suspects[ip] = time.time()

    def add(self, p, payload=b""):
        if p["proto"] not in ("TCP", "UDP", "DNS", "ICMP"):
            return
        with self.lock:
            k = self._key(p)
            f = self.flows.get(k)
            if f is None:
                f = self.flows[k] = Flow(p)
                self.dst_arrivals[p["dst_ip"]].append((p["ts"], p["src_ip"]))
            f.t1 = p["ts"]
            fwd = p["src_ip"] == f.init_ip and (p["proto"] == "ICMP" or p["sport"] == f.init_port)
            if fwd:
                f.fwd += 1
                f.fbytes += p.get("paylen", 0)
            else:
                f.bwd += 1
                f.bbytes += p.get("paylen", 0)
            if p["proto"] == "TCP":
                fl = p.get("tcp_flags", 0)
                if fl & 0x02 and not fl & 0x10:
                    f.syn += 1
                elif fl & 0x02 and fl & 0x10:
                    f.synack += 1
                elif fl & 0x10 and fwd:
                    f.ack_f += 1
                if fl & 0x01:
                    if fwd:
                        f.fin_f += 1
                    else:
                        f.fin_b += 1
                if fl & 0x04:
                    f.rst += 1
                if p.get("paylen", 0) > 0:
                    d = 0 if fwd else 1
                    if p["seq"] in f.seen[d]:
                        f.retrans += 1
                        p["retrans"] = True
                    elif len(f.seen[d]) < 300:
                        f.seen[d].add(p["seq"])
                if p.get("http_code"):
                    f.http = p["http_code"]
                if (f.fin_f and f.fin_b) or f.rst:
                    f.closed_at = f.closed_at or p["ts"]
            elif p["proto"] == "DNS":
                if p["dns_qr"] == 0:
                    f.dns_q += 1
                else:
                    f.dns_r += 1
                    f.rcode = p["dns_rcode"]
            elif p["proto"] == "ICMP":
                if p.get("icmp_type") == 8:
                    f.icmp_req += 1
                elif p.get("icmp_type") == 0:
                    f.icmp_rep += 1

    # ----------------------------------------------------------------- verdict
    @staticmethod
    def classify(f):
        """-> (verdict, reason). verdict: normal | fault | skip"""
        if f.fwd > 300:
            return "skip", "very high packet rate (possible flood)"
        if f.proto == "TCP":
            if f.rst and not f.synack:
                return "fault", "connection refused (RST to SYN)"
            if f.rst:
                return "fault", "connection reset mid-transfer"
            if f.syn and not f.synack:
                return "fault", "no reply to SYN (timeout / dropped)"
            if not f.syn:
                return "skip", "started before capture"
            if f.http >= 500:
                return "fault", f"HTTP {f.http} server error"
            if f.http == 404:
                return "fault", "HTTP 404 not found"
            if f.retrans and f.retrans / max(f.fwd + f.bwd, 1) > 0.1:
                return "fault", "heavy retransmission (packet loss)"
            if f.synack and (f.ack_f or f.fbytes or f.bbytes):
                return "normal", "TCP handshake completed, transfer finished"
            return "skip", "incomplete handshake"
        if f.proto == "UDP":
            if f.dns_q:
                if not f.dns_r:
                    return "fault", "DNS query without answer"
                if f.rcode == 3:
                    return "fault", "DNS NXDOMAIN (server not found)"
                if f.rcode:
                    return "fault", f"DNS error rcode {f.rcode}"
                return "normal", "DNS query answered"
            if f.fwd and f.bwd:
                return "normal", "UDP request answered"
            return "skip", "one-way UDP"
        if f.proto == "ICMP":
            if f.icmp_req and not f.icmp_rep:
                return "fault", "ping without reply"
            if f.icmp_req and f.icmp_rep:
                return "normal", "ping answered"
        return "skip", "not classified"

    def _service(self, f):
        if f.proto == "ICMP":
            return "eco_i"
        table = TCP_SERVICES if f.proto == "TCP" else UDP_SERVICES
        return table.get(f.resp_port, "private")

    def _record(self, f):
        svc = self._service(f)
        now = f.t1
        hist = self.recent[f.resp_ip]
        last2 = [s for (t, s) in hist if now - t <= 2.0]
        count = len(last2) + 1
        same = (sum(1 for s in last2 if s == svc) + 1) / count
        dsc = sum(1 for (_, s) in hist if s == svc) + 1
        hist.append((now, svc))
        return {"ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f.t0)), "src_name": f.init_name, "dst_name": f.resp_name,
                "src_ip": f.init_ip, "dst_ip": f.resp_ip, "protocol_type": {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp"}[f.proto],
                "service": svc, "flag": "SF", "src_bytes": f.fbytes, "dst_bytes": f.bbytes,
                "duration": int(max(f.t1 - f.t0, 0)), "count": count, "same_srv_rate": round(same, 2),
                "diff_srv_rate": round(1 - same, 2), "dst_host_srv_count": dsc, "logged_in": 0, "is_guest_login": 0,
                "label": "normal", "approx_fields": "logged_in,is_guest_login"}

    def sweep(self, now=None):
        """Finalize finished / idle flows. Returns list of events: ('normal', record) | ('fault', dict)."""
        now = now or time.time()
        done, events = [], []
        with self.lock:
            for k, f in list(self.flows.items()):
                if (f.closed_at and now - f.closed_at > 1.5) or now - f.t1 > self.idle:
                    done.append(self.flows.pop(k))
        for f in done:
            verdict, reason = self.classify(f)
            suspect = any(ip in self.suspects and now - self.suspects[ip] < 30 for ip in (f.init_ip, f.resp_ip))
            if verdict == "normal" and suspect:
                verdict, reason = "skip", "involves a host flagged as attacker"
            concurrent = self._contention(f) if verdict in ("normal", "fault") else 0
            if concurrent >= 2:
                # two or more DIFFERENT hosts reached for the same destination around the same moment:
                # this is contention/traffic, not a plain normal-or-fault connection - route it separately.
                rec = self._record(f)
                rec["label"], rec["concurrent_sources"], rec["underlying_verdict"] = "traffic", concurrent, verdict
                if self.traffic_rows_in_file < self.max_rows:
                    self._append(rec, TRAFFIC_CSV, TRAFFIC_COLUMNS)
                    self.traffic_rows_in_file += 1
                    self.counts["traffic_saved"] += 1
                events.append(("traffic", rec))
            elif verdict == "normal":
                rec = self._record(f)
                if self.rows_in_file < self.max_rows:
                    self._append(rec, NORMAL_CSV, COLUMNS)
                    self.rows_in_file += 1
                    self.counts["normal_saved"] += 1
                events.append(("normal", rec))
            elif verdict == "fault":
                key = (f.init_ip, f.resp_ip, reason)
                if now - self._fault_seen.get(key, 0) > 10:         # de-duplicate bursts
                    self._fault_seen[key] = now
                    ev = {"ts": time.strftime("%H:%M:%S", time.localtime(f.t1)), "src": f.init_name, "dst": f.resp_name,
                          "src_ip": f.init_ip, "dst_ip": f.resp_ip, "proto": f.proto, "reason": reason}
                    self.faults.appendleft(ev)
                    self.counts["faulty"] += 1
                    events.append(("fault", ev))
            else:
                self.counts["skipped"] += 1
        return events

    def _contention(self, f):
        """How many DISTINCT sources reached for f's destination within contention_window of f's start."""
        entries = self.dst_arrivals.get(f.resp_ip)
        if not entries:
            return 0
        distinct = {s for (t, s) in entries if abs(t - f.t0) <= self.contention_window}
        return len(distinct)

    # ----------------------------------------------------------------- file
    @staticmethod
    def _count_rows(path):
        if not os.path.exists(path):
            return 0
        with open(path) as fh:
            return max(sum(1 for _ in fh) - 1, 0)

    @staticmethod
    def _append(rec, path, columns):
        os.makedirs(DATA_DIR, exist_ok=True)
        new = not os.path.exists(path)
        with open(path, "a", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
            if new:
                w.writeheader()
            w.writerow(rec)
