#!/usr/bin/env python3
"""
feature_extractor.py - capture a window with tshark and turn it into features.

Features are things you can really compute from packets (no KDD-only fields),
so the same code is used for TRAINING data and for LIVE detection.
"""
import csv
import io
import subprocess
from collections import defaultdict

FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst", "ip.proto", "tcp.srcport", "tcp.dstport",
    "tcp.flags", "frame.len", "udp.dstport", "icmp.type", "dns.flags.response",
    "dns.flags.rcode", "dns.qry.name", "http.response.code",
    "tcp.analysis.retransmission",
]


# Fixed, ordered numeric feature list (used for training AND live prediction)
FEATURE_NAMES = [
    "pkts", "tcp_pkts", "udp_pkts", "icmp_pkts", "icmp_echo", "syn", "synack", "rst",
    "fin", "retrans", "dns_queries", "dns_responses", "dns_nxdomain", "dns_servfail",
    "http_404", "http_2xx", "http_3xx", "http_4xx", "http_5xx", "pkts_per_sec",
    "bytes_per_sec", "avg_pkt_size", "syn_rate", "udp_rate", "icmp_echo_rate",
    "half_open_ratio", "rst_ratio", "tcp_ratio", "udp_ratio", "icmp_ratio",
    "retrans_ratio", "unique_dst_ips", "max_ports_per_src", "max_syn_per_src",
    "login_port_syn", "dns_unanswered",
]


def capture_window(iface="s1-eth3", seconds=5, path="/tmp/win.pcap"):
    """Capture `seconds` of traffic (needs root). Returns the pcap path."""
    subprocess.run(["tshark", "-q", "-i", iface, "-a", f"duration:{seconds}", "-w", path],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return path


def read_pcap(path):
    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "separator=,",
           "-E", "header=y", "-E", "occurrence=f"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return list(csv.DictReader(io.StringIO(out)))


def _int(x, base=10, default=0):
    try:
        return int(x, base)
    except (ValueError, TypeError):
        return default


def extract_features(rows, window_seconds=5, exclude=()):
    f = defaultdict(float)
    src_count = defaultdict(int)
    syn_ports = defaultdict(set)      # src -> distinct dst ports probed with SYN
    syn_per_src = defaultdict(int)
    dst_ips, total_bytes = set(), 0
    http = defaultdict(int)
    port22_21_syn = defaultdict(int)

    for r in rows:
        f["pkts"] += 1
        if r["ip.src"] and r["ip.src"] not in exclude:
            src_count[r["ip.src"]] += 1
        total_bytes += _int(r["frame.len"])
        proto = r["ip.proto"]
        if r["ip.dst"]:
            dst_ips.add(r["ip.dst"])

        if proto == "6":                                   # TCP
            f["tcp_pkts"] += 1
            flags = _int(r["tcp.flags"], 16)
            syn, ack = flags & 0x02, flags & 0x10
            if syn and not ack:
                f["syn"] += 1
                src, dport = r["ip.src"], r["tcp.dstport"]
                syn_ports[src].add(dport)
                syn_per_src[src] += 1
                if dport in ("22", "21"):
                    port22_21_syn[src] += 1
            elif syn and ack:
                f["synack"] += 1
            if flags & 0x04:
                f["rst"] += 1
            if flags & 0x01:
                f["fin"] += 1
            if r["tcp.analysis.retransmission"]:
                f["retrans"] += 1
        elif proto == "17":
            f["udp_pkts"] += 1
        elif proto == "1":
            f["icmp_pkts"] += 1
            if r["icmp.type"] == "8":
                f["icmp_echo"] += 1

        if r["dns.flags.response"] == "0":
            f["dns_queries"] += 1
        elif r["dns.flags.response"] == "1":
            f["dns_responses"] += 1
            if r["dns.flags.rcode"] == "3":
                f["dns_nxdomain"] += 1
            elif r["dns.flags.rcode"] == "2":
                f["dns_servfail"] += 1

        code = r["http.response.code"]
        if code:
            http[code[0] + "xx"] += 1
            if code == "404":
                f["http_404"] += 1

    w = float(window_seconds)
    n = max(f["pkts"], 1)
    syn = f["syn"]
    f["window"] = w
    f["pkts_per_sec"] = f["pkts"] / w
    f["bytes_per_sec"] = total_bytes / w
    f["avg_pkt_size"] = total_bytes / n
    f["syn_rate"] = syn / w
    f["udp_rate"] = f["udp_pkts"] / w
    f["icmp_echo_rate"] = f["icmp_echo"] / w
    f["half_open_ratio"] = max(syn - f["synack"], 0) / syn if syn else 0.0
    f["rst_ratio"] = f["rst"] / syn if syn else 0.0
    f["tcp_ratio"] = f["tcp_pkts"] / n
    f["udp_ratio"] = f["udp_pkts"] / n
    f["icmp_ratio"] = f["icmp_pkts"] / n
    f["retrans_ratio"] = f["retrans"] / max(f["tcp_pkts"], 1)
    f["unique_dst_ips"] = len(dst_ips)
    f["max_ports_per_src"] = max((len(p) for p in syn_ports.values()), default=0)
    f["max_syn_per_src"] = max(syn_per_src.values(), default=0)
    f["login_port_syn"] = max(port22_21_syn.values(), default=0)
    f["dns_unanswered"] = max(f["dns_queries"] - f["dns_responses"], 0)
    f["http_2xx"], f["http_3xx"] = http["2xx"], http["3xx"]
    f["http_4xx"], f["http_5xx"] = http["4xx"], http["5xx"]
    top = max(syn_per_src, key=syn_per_src.get) if syn_per_src else None
    res = dict(f)
    for k in FEATURE_NAMES:
        res.setdefault(k, 0.0)
    res["top_src"] = top
    res["top_talker"] = max(src_count, key=src_count.get) if src_count else None
    return res


if __name__ == "__main__":
    import json
    p = capture_window()
    print(json.dumps(extract_features(read_pcap(p)), indent=2))
