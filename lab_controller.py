#!/usr/bin/env python3
"""
lab_controller.py  -  Mininet lab with a tiny local control API.

Run (needs root):   sudo python3 lab_controller.py
Control API (localhost only, port 9000), later called by Flask:
    GET /status
    GET /normal?on=1|0          start/stop background normal traffic
    GET /attack?type=syn_flood  (syn_flood|udp_flood|icmp_flood|port_scan|brute_force)
    GET /fault?type=dns_down    (dns_down|nxdomain|web_down|web_up|missing_page|
                                 loss|loss_off|drop|drop_off|dns_up)
    GET /stop_attack
    GET /reset

Topology:  h1 (attacker 10.0.0.1)  h2 (user 10.0.0.2)
           h3 (web+DNS server 10.0.0.3)  h4 (monitor 10.0.0.4)   all on s1
Capture the server side with:  tshark -i s1-eth3

SAFETY: attacks run ONLY between your own virtual hosts inside Mininet.
"""
import ipaddress
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel

SERVER = "10.0.0.3"
WEB_CMD = "python3 -m http.server 80 --directory /tmp/www"
DNS_CMD = ("dnsmasq --conf-file=/dev/null --no-resolv --no-hosts "
           f"--listen-address={SERVER} --bind-interfaces "
           f"--address=/web.lab/{SERVER} --pid-file=/tmp/dnsmasq_h3.pid")

# Rate-limited so the lab stays responsive (about 500 packets/sec) and auto-stops.
ATTACKS = {
    "syn_flood":   "hping3 -S -i u2000 -p 80 {t}",
    "udp_flood":   "hping3 --udp -i u2000 -p 53 -d 512 {t}",
    "icmp_flood":  "hping3 --icmp -i u2000 {t}",
    "port_scan":   "nmap -sS -T4 -p 1-1000 {t}",
    "brute_force": "for i in $(seq 1 300); do nc -z -w1 {t} 22; sleep 0.05; done",
}
ATTACK_SECONDS = 30

net = None
lock = threading.Lock()          # Mininet's cmd() is not thread-safe
state = {"normal": False, "attack": None, "fault": None}


def setup_servers():
    h3 = net.get("h3")
    h3.cmd("mkdir -p /tmp/www && echo '<h1>Lab web server</h1>' > /tmp/www/index.html")
    h3.cmd(WEB_CMD + " > /dev/null 2>&1 &")
    h3.cmd(DNS_CMD + " > /dev/null 2>&1 &")


def normal_traffic_loop():
    h2 = net.get("h2")
    while True:
        if state["normal"]:
            with lock:
                h2.cmd(f"curl -s -m 2 http://{SERVER}/ > /dev/null")
                h2.cmd(f"ping -c 1 -W 1 {SERVER} > /dev/null")
                h2.cmd(f"dig +time=1 +tries=1 @{SERVER} web.lab > /dev/null")
        time.sleep(1)


def do_attack(kind):
    if kind not in ATTACKS:
        return {"error": "unknown attack"}
    cmd = ATTACKS[kind].format(t=SERVER)
    with lock:
        net.get("h1").cmd(f"timeout {ATTACK_SECONDS} bash -c '{cmd}' > /dev/null 2>&1 &")
    state["attack"] = kind
    return {"ok": f"{kind} started for {ATTACK_SECONDS}s"}


def stop_attack():
    with lock:
        net.get("h1").cmd("pkill hping3; pkill nmap; pkill -f 'nc -z'")
    state["attack"] = None
    return {"ok": "attacks stopped"}


def do_fault(kind):
    h2, h3 = net.get("h2"), net.get("h3")
    with lock:
        if kind == "web_down":
            h3.cmd("pkill -f 'http.server 80'")                  # -> connection refused
        elif kind == "web_up":
            h3.cmd(WEB_CMD + " > /dev/null 2>&1 &")
        elif kind == "dns_down":
            h3.cmd(f"kill $(cat /tmp/dnsmasq_h3.pid)")           # -> DNS timeouts
        elif kind == "dns_up":
            h3.cmd(DNS_CMD + " > /dev/null 2>&1 &")
        elif kind == "nxdomain":
            h2.cmd(f"dig +time=1 +tries=1 @{SERVER} nothere.lab > /dev/null")
        elif kind == "missing_page":
            for _ in range(5):
                h2.cmd(f"curl -s -m 2 http://{SERVER}/missing.html > /dev/null")  # -> HTTP 404
        elif kind == "loss":
            h3.intf().config(delay="200ms", loss=15)             # latency + packet loss
        elif kind == "loss_off":
            h3.intf().config(delay="5ms", loss=0)
        elif kind == "drop":                                     # -> connection timeout
            h3.cmd("iptables -A INPUT -p tcp --dport 80 -j DROP")
        elif kind == "drop_off":
            h3.cmd("iptables -D INPUT -p tcp --dport 80 -j DROP")
        else:
            return {"error": "unknown fault"}
    state["fault"] = None if kind.endswith(("_up", "_off")) else kind
    return {"ok": f"fault '{kind}' applied"}


def reset():
    stop_attack()
    for k in ("loss_off", "drop_off", "web_up", "dns_up"):
        try:
            do_fault(k)
        except Exception:
            pass
    state.update({"attack": None, "fault": None})
    return {"ok": "reset"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/status":
            out = dict(state)
        elif u.path == "/normal":
            state["normal"] = q.get("on", "1") == "1"
            out = {"ok": f"normal traffic={state['normal']}"}
        elif u.path == "/attack":
            out = do_attack(q.get("type", ""))
        elif u.path == "/stop_attack":
            out = stop_attack()
        elif u.path == "/fault":
            out = do_fault(q.get("type", ""))
        elif u.path == "/reset":
            out = reset()
        elif u.path in ("/block", "/unblock"):
            try:
                ip = str(ipaddress.ip_address(q.get("ip", "")))
                flag = "-I" if u.path == "/block" else "-D"
                with lock:
                    net.get("h3").cmd(f"iptables {flag} INPUT -s {ip} -j DROP")
                out = {"ok": f"{u.path[1:]} {ip}"}
            except ValueError:
                out = {"error": "invalid ip"}
        else:
            out = {"error": "not found"}
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def main():
    global net
    setLogLevel("warning")
    net = Mininet(link=TCLink)
    s1 = net.addSwitch("s1", failMode="standalone")   # learning switch, no controller needed
    for i in range(1, 5):
        h = net.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
        net.addLink(h, s1, bw=10, delay="5ms", loss=0)
    net.start()
    setup_servers()
    threading.Thread(target=normal_traffic_loop, daemon=True).start()
    srv = HTTPServer(("127.0.0.1", 9000), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("Lab ready. Control API on http://127.0.0.1:9000  |  capture with: tshark -i s1-eth3")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        net.stop()


if __name__ == "__main__":
    main()
