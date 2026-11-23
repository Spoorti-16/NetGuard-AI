#!/usr/bin/env python3
"""
realnet_controller.py - builds the real-time network in Mininet and exposes a local control API (port 9000).

   4 routers (ring)  -  8 switches (2 per router)  -  10 hosts per switch  =  80 hosts   (see network_config.json)

Run (root):  sudo python3 realnet_controller.py        (stop with Ctrl+C, clean up with: sudo mn -c)
Needs about 4 GB RAM free and a few CPU cores; start-up takes 30-60 seconds.

Control API (127.0.0.1:9000)        /status  /normal?on=1|0  /attack?type=&src=&dst=&duration=&rate=  /stop_attack
                                    /fault?type=  /send?src=&dst=&msg=  /block?ip=  /unblock?ip=  /reset
                                    /ping_test?src=&dst=&count=&interval=        (deterministic ICMP injection)
                                    /custom_test?src=&dst=&proto=&port=&count=&interval=  (finite custom packet injection)
Attacks run only between your own virtual hosts. Real/remote participants are only ever the TARGET or SOURCE of
normal traffic they generate themselves - this controller never launches attacks from or at them.
"""
import ipaddress
import json
import os
import re
import shlex
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from mininet.link import Intf
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node, OVSKernelSwitch

import netplan

ATTACKS = {
    "syn_flood": "hping3 -S -i u2000 -p 80 {t}",
    "udp_flood": "hping3 --udp -i u2000 -p 53 -d 512 {t}",
    "icmp_flood": "hping3 --icmp -i u2000 {t}",
    "port_scan": "nmap -sS -T4 -p 1-1000 {t}",
    "brute_force": "for i in $(seq 1 300); do nc -z -w1 {t} 22; sleep 0.05; done",
}
ATTACK_SECONDS = 30
BG_SCRIPT = """#!/bin/bash
# background 'office' traffic for one host: random ping / web / DNS / chat message to random peers
ME="$1"; WEB="$2"; DNS="$3"
while true; do
  sleep $((RANDOM % 6 + 2))
  PEER=$(shuf -n1 /tmp/ids_peers.txt)
  case $((RANDOM % 4)) in
    0) ping -c1 -W1 "$PEER" >/dev/null 2>&1 ;;
    1) curl -s -m2 "http://$WEB/" >/dev/null 2>&1 ;;
    2) dig +time=1 +tries=1 @"$DNS" web.lab >/dev/null 2>&1 ;;
    3) echo "hello from $ME" | nc -w1 "$PEER" 9000 >/dev/null 2>&1 ;;
  esac
done
"""


class LinuxRouter(Node):
    def config(self, **params):
        r = super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")
        return r

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super().terminate()


net, plan, root = None, None, None
lock = threading.Lock()
state = {"normal": False, "attack": None, "fault": None}


def build():
    global net, plan, root
    plan = netplan.build_plan()
    net = Mininet(controller=None, build=False, autoSetMacs=False)
    routers = {r["name"]: net.addHost(r["name"], cls=LinuxRouter, ip=None) for r in plan["routers"]}
    sws = {s["name"]: net.addSwitch(s["name"], cls=OVSKernelSwitch, failMode="standalone") for s in plan["switches"]}
    for s in plan["switches"]:
        net.addLink(sws[s["name"]], routers[s["router"]], port1=s["uplink_port"], intfName2=s["router_intf"],
                    params2={"ip": f"{s['gw']}/24"})
    for h in plan["hosts"]:
        gw = next(s["gw"] for s in plan["switches"] if s["name"] == h["switch"])
        host = net.addHost(h["name"], ip=f"{h['ip']}/24", mac=h["mac"], defaultRoute=f"via {gw}")
        net.addLink(host, sws[h["switch"]], port2=h["port"])
    for l in plan["rlinks"]:
        net.addLink(routers[l["a"]], routers[l["b"]], intfName1=l["a_intf"], intfName2=l["b_intf"],
                    params1={"ip": f"{l['a_ip']}/30"}, params2={"ip": f"{l['b_ip']}/30"})
    for rh in plan["real_hosts"]:                                   # physical NIC plugged into a switch
        if os.path.exists(f"/sys/class/net/{rh['nic']}"):
            Intf(rh["nic"], node=sws[rh["switch"]])
        else:
            print(f"WARNING: NIC {rh['nic']} for {rh['name']} not found - skipped")
    gw = plan["gateway"]
    if gw:                                                          # veth between root namespace and router r1 (WireGuard side)
        root = Node("root", inNamespace=False)
        net.addLink(root, routers[gw["router"]], intfName1="ids-gw0", intfName2=f"{gw['router']}-gw",
                    params1={"ip": f"{gw['root_ip']}/30"}, params2={"ip": f"{gw['router_ip']}/30"})
    net.start()
    for r, routes in plan["routes"].items():
        for subnet, via in routes:
            routers[r].cmd(f"ip route add {subnet} via {via}")
    if gw:
        root.cmd("sysctl -w net.ipv4.ip_forward=1")
        root.cmd(f"ip route add 10.0.0.0/16 via {gw['router_ip']}")
        root.cmd(f"ip route add 10.100.0.0/16 via {gw['router_ip']}")
        routers[gw["router"]].cmd(f"ip route add {gw['remote_subnet']} via {gw['root_ip']}")


def setup_services():
    if not plan["hosts"]:
        return
    web = net.get(plan.get("web_host")) if plan.get("web_host") else None
    dns = net.get(plan.get("dns_host")) if plan.get("dns_host") else None
    if web and any(h["name"] == plan.get("web_host") for h in plan["hosts"]):
        wip = next(h["ip"] for h in plan["hosts"] if h["name"] == plan["web_host"])
        web.cmd("mkdir -p /tmp/www && echo '<h1>Lab web server</h1>' > /tmp/www/index.html")
        web.cmd("python3 -m http.server 80 --directory /tmp/www > /dev/null 2>&1 &")
    if dns and any(h["name"] == plan.get("dns_host") for h in plan["hosts"]):
        wip = next((h["ip"] for h in plan["hosts"] if h["name"] == plan.get("web_host")), "10.0.8.20")
        dip = next(h["ip"] for h in plan["hosts"] if h["name"] == plan["dns_host"])
        dns.cmd(f"dnsmasq --conf-file=/dev/null --no-resolv --no-hosts --listen-address={dip} --bind-interfaces "
                f"--address=/web.lab/{wip} --pid-file=/tmp/dnsmasq_dns.pid > /dev/null 2>&1 &")
    for h in plan["hosts"]:                                          # message receiver on every host (port 9000)
        try:
            net.get(h["name"]).sendCmd(f"nc -lk 9000 >> /tmp/chat_{h['name']}.log 2>&1 &")
        except Exception:
            pass
    with open("/tmp/ids_peers.txt", "w") as fh:
        fh.write("\n".join(h["ip"] for h in plan["hosts"]) + "\n")
    with open("/tmp/ids_bg.sh", "w") as fh:
        fh.write(BG_SCRIPT)


def host_ip(name):
    all_h = plan["hosts"] + plan.get("remote_hosts", []) + plan.get("real_hosts", [])
    if plan.get("gateway"):
        all_h = all_h + [{"name": "admin_gw", "ip": plan["gateway"]["root_ip"]}]
    for h in all_h:
        if h["name"] == name or h.get("label") == name:
            return h["ip"]
    return None


def normal(on):
    with lock:
        if on and not state["normal"] and plan["hosts"]:
            wip, dip = host_ip(plan.get("web_host")), host_ip(plan.get("dns_host"))
            for h in plan["hosts"][:12]:
                try:
                    net.get(h["name"]).sendCmd(f"bash /tmp/ids_bg.sh {h['ip']} {wip} {dip} > /dev/null 2>&1 &")
                except Exception:
                    pass
        elif not on:
            for h in plan["hosts"]:
                try:
                    net.get(h["name"]).cmd("pkill -f ids_bg.sh")
                except Exception:
                    pass
    state["normal"] = bool(on)
    return {"ok": "active"}


def attack(kind, src, dst, duration=None, rate=None):
    if kind not in ATTACKS:
        return {"error": "unknown attack"}
    dst_ip = host_ip(dst) or (plan.get("gateway") and plan["gateway"]["root_ip"]) or "10.99.0.1"
    dur = max(5, min(int(duration or ATTACK_SECONDS), 120))
    interval_us = max(200, min(int(rate or 2000), 20000))
    cmd = ATTACKS[kind].format(t=dst_ip).replace("u2000", f"u{interval_us}")
    r1 = net.get("r1")
    if r1:
        with lock:
            r1.cmd(f"timeout {dur} bash -c {shlex.quote(cmd)} > /dev/null 2>&1 &")
    state["attack"] = f"{kind} to {dst_ip}"
    return {"ok": f"{kind} against {dst_ip} for {dur}s"}


def _parse_ping(out, fallback_count):
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out or "")
    sent, recv = (int(m.group(1)), int(m.group(2))) if m else (fallback_count, 0)
    rtt = re.search(r"= [\d.]+/([\d.]+)/", out or "")
    return {"sent": sent, "received": recv, "loss_pct": round((sent - recv) / sent * 100, 1) if sent else 0.0,
            "rtt_avg_ms": float(rtt.group(1)) if rtt else None}


def ping_test(src, dst, count, interval):
    """Deterministic ICMP ping injection between hosts."""
    sip, dip = host_ip(src), host_ip(dst)
    dip = dip or "10.99.0.1"
    count = max(1, min(int(count), 300))
    interval = max(0.05, min(float(interval), 2.0))
    budget = min(count * interval + 5, 60)
    node = net.get(src) if src in net else net.get("r1")
    with lock:
        out = node.cmd(f"timeout {budget:.0f} ping -c {count} -i {interval} -W1 {dip}")
    return dict(_parse_ping(out, count), ok=True)


def custom_test(src, dst, proto, port, count, interval_ms):
    """Finite, parameterised packet injection."""
    sip, dip = host_ip(src), host_ip(dst)
    dip = dip or "10.99.0.1"
    proto = proto if proto in ("icmp", "tcp", "udp") else "icmp"
    count = max(1, min(int(count), 500))
    interval_ms = max(50, min(int(interval_ms), 2000))
    flag = {"icmp": "1", "tcp": "S", "udp": "2"}[proto]
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        port_i = 0
    port_arg = f"-p {port_i}" if proto != "icmp" and 0 < port_i < 65536 else ""
    cmd = f"hping3 -{flag} {port_arg} -c {count} -i u{interval_ms * 1000}"
    budget = min(count * interval_ms / 1000 + 5, 60)
    node = net.get(src) if src in net else net.get("r1")
    with lock:
        out = node.cmd(f"timeout {budget:.0f} bash -c {shlex.quote(cmd + ' ' + dip)}")
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out or "")
    sent, recv = (int(m.group(1)), int(m.group(2))) if m else (count, 0)
    return {"ok": True, "proto": proto, "port": port_i, "sent": sent, "received": recv,
            "loss_pct": round((sent - recv) / sent * 100, 1) if sent else 0.0}


def stop_attack():
    with lock:
        for h in plan["hosts"]:
            net.get(h["name"]).cmd("pkill hping3; pkill nmap")
    state["attack"] = None
    return {"ok": "attacks stopped"}


def fault(kind):
    web, dns = net.get(plan["web_host"]), net.get(plan["dns_host"])
    client = net.get("h1_2")
    wip, dip = host_ip(plan["web_host"]), host_ip(plan["dns_host"])
    wport = web.defaultIntf().name
    with lock:
        if kind == "web_down":
            web.cmd("pkill -f 'http.server 80'")
        elif kind == "web_up":
            web.cmd("python3 -m http.server 80 --directory /tmp/www > /dev/null 2>&1 &")
        elif kind == "dns_down":
            dns.cmd("kill $(cat /tmp/dnsmasq_dns.pid)")
        elif kind == "dns_up":
            dns.cmd(f"dnsmasq --conf-file=/dev/null --no-resolv --no-hosts --listen-address={dip} --bind-interfaces "
                    f"--address=/web.lab/{wip} --pid-file=/tmp/dnsmasq_dns.pid > /dev/null 2>&1 &")
        elif kind == "nxdomain":
            client.cmd(f"dig +time=1 +tries=1 @{dip} nothere.lab > /dev/null")
        elif kind == "missing_page":
            for _ in range(5):
                client.cmd(f"curl -s -m 2 http://{wip}/missing.html > /dev/null")
        elif kind == "loss":
            web.cmd(f"tc qdisc replace dev {wport} root netem delay 200ms loss 15%")
        elif kind == "loss_off":
            web.cmd(f"tc qdisc del dev {wport} root")
        elif kind == "drop":
            web.cmd("iptables -A INPUT -p tcp --dport 80 -j DROP")
        elif kind == "drop_off":
            web.cmd("iptables -D INPUT -p tcp --dport 80 -j DROP")
        else:
            return {"error": "unknown fault"}
    state["fault"] = None if kind.endswith(("_up", "_off")) else kind
    return {"ok": f"fault '{kind}' applied"}


def send(src, dst, msg):
    sip, dip = host_ip(src), host_ip(dst)
    if not sip or not dip or src == dst:
        return {"error": "send works between two valid hosts"}
    msg = msg.replace("\n", " ")[:200]
    with lock:
        node = net.get(src) if (net and src in net) else (net.get("r1") if (net and "r1" in net) else None)
        if node:
            node.cmd(f"echo {shlex.quote(msg)} | nc -w2 {dip} 9000 > /dev/null 2>&1 &")
    return {"ok": f"{src} -> {dst}: sent"}


def block(ip, on=True):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return {"error": "invalid ip"}
    h = next((x for x in plan["hosts"] if x["ip"] == ip), None)
    router = h["router"] if h else (plan["gateway"]["router"] if plan.get("gateway") else "r1")
    if not router or (net and router not in net):
        router = "r1"
    flag = "-I" if on else "-D"
    with lock:
        if net and router in net:
            net.get(router).cmd(f"iptables {flag} FORWARD -s {ip} -j DROP")
            net.get(router).cmd(f"iptables {flag} INPUT -s {ip} -j DROP")
        web_name = plan.get("web_host")
        if web_name and net and web_name in net:
            net.get(web_name).cmd(f"iptables {flag} INPUT -s {ip} -j DROP")
    return {"ok": f"{'block' if on else 'unblock'} {ip} on {router}"}


def reset():
    stop_attack()
    for k in ("loss_off", "drop_off", "web_up", "dns_up"):
        try:
            fault(k)
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
        try:
            if u.path == "/status":
                out = dict(state, hosts=len(plan["hosts"]))
            elif u.path == "/normal":
                out = normal(q.get("on", "1") == "1")
            elif u.path == "/attack":
                out = attack(q.get("type", ""), q.get("src"), q.get("dst"), q.get("duration"), q.get("rate"))
            elif u.path == "/stop_attack":
                out = stop_attack()
            elif u.path == "/ping_test":
                out = ping_test(q.get("src", ""), q.get("dst", ""), q.get("count", 10), q.get("interval", 0.3))
            elif u.path == "/custom_test":
                out = custom_test(q.get("src", ""), q.get("dst", ""), q.get("proto", "icmp"), q.get("port", 0),
                                  q.get("count", 10), q.get("interval", 300))
            elif u.path == "/fault":
                out = fault(q.get("type", ""))
            elif u.path == "/send":
                out = send(q.get("src", ""), q.get("dst", ""), q.get("msg", ""))
            elif u.path in ("/block", "/unblock"):
                out = block(q.get("ip", ""), u.path == "/block")
            elif u.path == "/reset":
                out = reset()
            else:
                out = {"error": "not found"}
        except Exception as e:
            out = {"error": str(e)}
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def main():
    setLogLevel("warning")
    print("Building network (4 routers, 8 switches, 80 hosts) ... this takes a minute")
    build()
    setup_services()
    srv = HTTPServer(("127.0.0.1", 9000), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("Network ready. Control API on http://127.0.0.1:9000 - now start: sudo python3 app.py")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        net.stop()


if __name__ == "__main__":
    main()
