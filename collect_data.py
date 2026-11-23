#!/usr/bin/env python3
"""
collect_data.py - builds YOUR labeled dataset from the Mininet lab.

Prereq: lab_controller.py is running in another terminal (sudo python3 lab_controller.py)
Run:    sudo python3 collect_data.py [windows_per_class]     (default 60, ~5 s each)
Output: data/flows.csv   (one row = one 5-second window, label = the scenario you ran)

Ground truth comes from the scenario itself, so no manual labelling is needed.
"""
import csv
import os
import sys
import threading
import time
import urllib.request

from feature_extractor import FEATURE_NAMES, capture_window, extract_features, read_pcap

API = "http://127.0.0.1:9000"
IFACE = "s1-eth3"          # switch port facing the server (h3)
WINDOW = 5

# restart_every = re-launch the attack every N windows (scans finish quickly)
SCENARIOS = {
    "normal":            {},
    "syn_flood":         {"attack": "syn_flood", "restart_every": 5},
    "udp_flood":         {"attack": "udp_flood", "restart_every": 5},
    "icmp_flood":        {"attack": "icmp_flood", "restart_every": 5},
    "port_scan":         {"attack": "port_scan", "restart_every": 1},
    "brute_force":       {"attack": "brute_force", "restart_every": 3},
    "dns_nxdomain":      {"trigger": "nxdomain"},
    "dns_down":          {"setup": "dns_down", "teardown": "dns_up"},
    "conn_refused":      {"setup": "web_down", "teardown": "web_up"},
    "conn_timeout":      {"setup": "drop", "teardown": "drop_off"},
    "http_404":          {"trigger": "missing_page"},
    "high_latency_loss": {"setup": "loss", "teardown": "loss_off"},
}


def api(path):
    try:
        return urllib.request.urlopen(API + path, timeout=10).read()
    except Exception as e:
        print("  API error:", path, e)


def run_scenario(label, sc, n_windows, writer):
    print(f"[{label}] {n_windows} windows")
    api("/reset")
    api("/normal?on=1")                       # background user traffic in every scenario
    if "setup" in sc:
        api(f"/fault?type={sc['setup']}")
    time.sleep(2)
    for w in range(n_windows):
        if "attack" in sc and w % sc["restart_every"] == 0:
            api("/stop_attack")
            api(f"/attack?type={sc['attack']}")
            time.sleep(1)
        if "trigger" in sc:                   # fire the fault 1 s into the window
            threading.Timer(1, api, args=(f"/fault?type={sc['trigger']}",)).start()
        feats = extract_features(read_pcap(capture_window(IFACE, WINDOW)), WINDOW)
        row = {k: feats.get(k, 0.0) for k in FEATURE_NAMES}
        row["label"] = label
        writer.writerow(row)
    if "teardown" in sc:
        api(f"/fault?type={sc['teardown']}")
    api("/stop_attack")


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    os.makedirs("data", exist_ok=True)
    new = not os.path.exists("data/flows.csv")
    with open("data/flows.csv", "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FEATURE_NAMES + ["label"])
        if new:
            writer.writeheader()
        for label, sc in SCENARIOS.items():
            run_scenario(label, sc, n, writer)
            fh.flush()
    api("/reset")
    print("Done -> data/flows.csv")


if __name__ == "__main__":
    main()
