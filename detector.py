#!/usr/bin/env python3
"""
detector.py - one brain for attacks AND faults.

decide(features, ml_predict=None) -> dict with:
    category : normal | attack | fault
    label    : e.g. syn_flood, port_scan, dns_down, conn_refused, http_404 ...
    confidence, threat_score (0-100), severity, evidence, cause, fix, source_ip

`ml_predict` is optional: a function(features)->(label, probability) wrapping your
trained Model B (RandomForest). When it agrees with the rules, confidence is high;
when it disagrees, the verdict is marked "needs_review".

Run live test (needs lab running + root):  sudo python3 detector.py
"""
from feature_extractor import capture_window, read_pcap, extract_features

# ---------- attack rules (thresholds: tune on YOUR captures) ----------
ATTACK_WEIGHT = {"syn_flood": 90, "udp_flood": 85, "icmp_flood": 80,
                 "brute_force": 70, "port_scan": 60}


def rule_attack(f):
    if f["syn_rate"] > 100 and f["half_open_ratio"] > 0.8 and f["max_ports_per_src"] < 5:
        return "syn_flood", f"SYN rate {f['syn_rate']:.0f}/s, {f['half_open_ratio']:.0%} half-open"
    if f["max_ports_per_src"] > 20:
        return "port_scan", f"one source probed {f['max_ports_per_src']} ports"
    if f["udp_rate"] > 200:
        return "udp_flood", f"UDP rate {f['udp_rate']:.0f}/s"
    if f["icmp_echo_rate"] > 100:
        return "icmp_flood", f"ICMP echo rate {f['icmp_echo_rate']:.0f}/s"
    if f["login_port_syn"] > 20 and f["max_ports_per_src"] <= 2:
        return "brute_force", f"{f['login_port_syn']} connection attempts to port 21/22"
    return None, ""


# ---------- fault rules ----------
FAULTS = {
    "dns_nxdomain": ("Server not found (NXDOMAIN)",
                     "Domain misspelled, record missing, or domain expired.",
                     "Check the name spelling and the DNS zone/record."),
    "dns_down": ("DNS not answering (timeout/SERVFAIL)",
                 "DNS server down, unreachable, misconfigured, or UDP/53 blocked.",
                 "Restart the DNS service, check reachability and firewall for port 53."),
    "conn_refused": ("Connection refused",
                     "Service not running, wrong port, or firewall REJECT.",
                     "Start the service, verify the port, review firewall rules."),
    "conn_timeout": ("Connection timed out",
                     "Host down, link down, routing problem, or firewall silently dropping.",
                     "Check link/host status, routing, and DROP rules."),
    "http_404": ("HTTP 404 Not Found",
                 "Wrong URL, file deleted/moved, wrong document root, or broken link.",
                 "Verify the URL and that the file exists in the web root."),
    "http_5xx": ("HTTP 5xx server error",
                 "Application crash, bad config, backend down, or server overloaded.",
                 "Check server logs and backend health; look for overload or attack."),
    "high_latency_loss": ("Slow connection / packet loss",
                          "Congestion, lossy link, low bandwidth, or overloaded server.",
                          "Check link quality and bandwidth; look at retransmission trend."),
}


def rule_fault(f):
    if f["dns_nxdomain"] > 0:
        return "dns_nxdomain", f"{int(f['dns_nxdomain'])} NXDOMAIN reply(ies)"
    if f["dns_servfail"] > 0 or f["dns_unanswered"] >= 3:
        return "dns_down", f"{int(f['dns_unanswered'])} DNS queries unanswered, SERVFAIL={int(f['dns_servfail'])}"
    if f["http_5xx"] > 0:
        return "http_5xx", f"{int(f['http_5xx'])} HTTP 5xx responses"
    if f["http_404"] > 0:
        return "http_404", f"{int(f['http_404'])} HTTP 404 responses (plain HTTP only)"
    if f["syn"] >= 2 and f["rst_ratio"] > 0.5 and f["max_ports_per_src"] < 5:
        return "conn_refused", f"{int(f['rst'])} RST for {int(f['syn'])} SYN"
    if f["syn"] >= 3 and f["synack"] == 0 and f["rst"] == 0:
        return "conn_timeout", f"{int(f['syn'])} SYN, no SYN-ACK or RST"
    if f["retrans_ratio"] > 0.05:
        return "high_latency_loss", f"retransmissions {f['retrans_ratio']:.0%} of TCP packets"
    return None, ""


def severity(score):
    return ("CRITICAL" if score >= 80 else "HIGH" if score >= 60 else
            "MEDIUM" if score >= 30 else "LOW")


def _decide(f, ml_predict=None):
    a_label, a_ev = rule_attack(f)
    ml_label, ml_conf = (ml_predict(f) if ml_predict else (None, None))
    out = {"category": "normal", "label": "normal", "confidence": 0.9,
           "threat_score": 5, "severity": "LOW", "evidence": "",
           "cause": "", "fix": "", "source_ip": f.get("top_talker") or f.get("top_src"),
           "ml_label": ml_label, "agreement": None}

    if a_label or (ml_label and ml_label not in ("normal",) and ml_label in ATTACK_WEIGHT):
        label = a_label or ml_label
        agree = (ml_label == a_label) if (ml_label and a_label) else None
        conf = 0.95 if agree else (0.7 if agree is None else 0.5)
        score = round(ATTACK_WEIGHT[label] * (0.6 + 0.4 * conf) / 0.95, 1)
        score = min(score, 100)
        out.update(category="attack", label=label, confidence=conf, threat_score=score,
                   severity=severity(score), evidence=a_ev or "ML only", agreement=agree,
                   cause="Attack traffic pattern", fix="Block source / rate-limit (see Response page)")
        if agree is False:
            out["needs_review"] = True
        return out

    fl, ev = rule_fault(f)
    if fl:
        title, cause, fix = FAULTS[fl]
        out.update(category="fault", label=fl, confidence=0.85, threat_score=20,
                   severity="MEDIUM", evidence=ev, cause=cause, fix=fix, title=title)
    return out



# ---------- explainability + wrappers ----------
import json as _json
import os as _os

_BASE = None
DRIVER_KEYS = ["syn_rate", "half_open_ratio", "max_ports_per_src", "udp_rate", "icmp_echo_rate",
               "rst_ratio", "dns_unanswered", "dns_nxdomain", "http_404", "http_5xx",
               "retrans_ratio", "pkts_per_sec"]


def _baseline():
    global _BASE
    if _BASE is None:
        p = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "models", "baseline.json")
        _BASE = _json.load(open(p)) if _os.path.exists(p) else {}
    return _BASE


def explain(f, top=4):
    """Key drivers: features whose value deviates most from the 'normal' baseline."""
    base, items = _baseline(), []
    for k in DRIVER_KEYS:
        obs, b = float(f.get(k, 0) or 0), float(base.get(k, 0.0))
        dev = abs(obs - b) / (abs(b) + 1.0)
        if dev > 0.2:
            items.append({"feature": k, "observed": round(obs, 3), "baseline": round(b, 3),
                          "deviation": round(dev, 2)})
    return sorted(items, key=lambda x: -x["deviation"])[:top]


def decide(f, ml_predict=None):
    v = _decide(f, ml_predict)
    v["drivers"] = explain(f)
    return v


def manual_fault(dns="ok", http_code=200, rtt_ms=20, loss_pct=0, tcp="ok"):
    """Diagnose a fault from values typed in a form (no capture needed)."""
    from feature_extractor import extract_features
    f = extract_features([], 5)
    if dns == "nxdomain":
        f["dns_nxdomain"] = 1
    elif dns == "servfail":
        f["dns_servfail"] = 1
    elif dns == "no_response":
        f["dns_queries"], f["dns_unanswered"] = 3, 3
    if tcp == "refused":
        f["syn"], f["rst"], f["rst_ratio"] = 3, 3, 1.0
    elif tcp == "timeout":
        f["syn"] = 3
    code = int(http_code)
    if code == 404:
        f["http_404"] = 1
    elif 500 <= code < 600:
        f["http_5xx"] = 1
    if float(loss_pct) > 3 or float(rtt_ms) > 300:
        f["retrans_ratio"] = 0.1
    label, ev = rule_fault(f)
    if not label:
        return {"category": "normal", "label": "normal", "evidence": "No fault indicators", "cause": "", "fix": ""}
    title, cause, fix = FAULTS[label]
    return {"category": "fault", "label": label, "title": title, "evidence": ev, "cause": cause, "fix": fix}

if __name__ == "__main__":
    import time
    print("Live monitor: capturing 5s windows on s1-eth3 (Ctrl+C to stop)")
    while True:
        feats = extract_features(read_pcap(capture_window()), 5)
        v = decide(feats)
        print(time.strftime("%H:%M:%S"), v["category"].upper(), v["label"],
              f"score={v['threat_score']} {v['severity']}", "|", v["evidence"])
