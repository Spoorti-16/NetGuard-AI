"""Flask routes for the real-time network view (admin only)."""
import urllib.parse

from flask import jsonify, render_template, request

import datasets
import db
import response_engine as resp
from netmonitor import netmon
from netplan import build_plan

PKT_FIELDS = ("id", "ts", "time_str", "direction", "src", "dst", "src_ip", "dst_ip", "proto", "sport", "dport", "length", "flags", "info", "ttl",
              "src_mac", "dst_mac", "iface", "payload_preview", "hex_dump", "seq", "ack", "window", "ihl", "ip_id", "ethertype")


def register(app, admin_required, body):
    def plan():
        return netmon.plan or build_plan()

    @app.route("/network")
    @admin_required
    def network():
        return render_template("network.html")

    @app.route("/api/net/topology")
    @admin_required
    def net_topology():
        p = plan()
        keep = ("name", "label", "ip", "mac", "switch", "router", "kind", "port", "occupied", "username")
        return jsonify(counts=p["counts"], routers=p["routers"], switches=p["switches"],
                       hosts=[{k: h.get(k) for k in keep} for h in p["hosts"] + p["real_hosts"] + p["remote_hosts"]],
                       rlinks=[{k: l[k] for k in ("a", "b", "subnet")} for l in p["rlinks"]],
                       gateway=p["gateway"], web_host=p["web_host"], dns_host=p["dns_host"], attacker_host=p["attacker_host"])

    @app.route("/api/net/<action>", methods=["POST"])
    @admin_required
    def net_action(action):
        d = body()
        if action == "start":
            return jsonify(netmon.start())
        if action == "stop":
            return jsonify(netmon.stop())
        if action == "payload":
            netmon.set_payload_preview(bool(d.get("on")))
            return jsonify(ok="payload preview " + ("ON" if d.get("on") else "OFF"))
        if action == "traffic":
            return jsonify(resp.lab_call(f"/normal?on={1 if d.get('on') else 0}"))
        if action == "send":
            p = plan()
            all_h = p["hosts"] + p.get("remote_hosts", []) + p.get("real_hosts", [])
            if p.get("gateway"):
                all_h.append({"name": "admin_gw", "label": "Admin Laptop", "ip": p["gateway"]["root_ip"]})
            names = {h["name"] for h in all_h} | {h.get("label") for h in all_h}
            src, dst, msg = str(d.get("src", "")), str(d.get("dst", "")), str(d.get("msg", "")).replace("\n", " ").strip()
            if src not in names or dst not in names or src == dst:
                return jsonify(error="choose two different participants"), 400
            if not msg or len(msg) > 200:
                return jsonify(error="message must be 1-200 characters"), 400
            s_obj = next((h for h in all_h if h["name"] == src or h.get("label") == src), None)
            d_obj = next((h for h in all_h if h["name"] == dst or h.get("label") == dst), None)
            sip = s_obj["ip"] if s_obj else "10.99.1.10"
            dip = d_obj["ip"] if d_obj else "10.99.0.1"
            s_label = s_obj.get("label", src) if s_obj else src
            d_label = d_obj.get("label", dst) if d_obj else dst
            db.add_message(s_label, sip, d_label, dip, msg)
            if netmon and netmon.sniffer:
                import time
                netmon.sniffer.ingest(
                    data=None, hatype=1, iface="test", ts=time.time(),
                    custom_pkt={
                        "proto": "TCP", "src_ip": sip, "dst_ip": dip, "sport": 5000, "dport": 9000,
                        "length": len(msg) + 40, "flags": "PSH,ACK",
                        "info": f"TEST: [{s_label} -> {d_label}]: \"{msg[:60]}\"",
                        "payload_preview": msg[:96]
                    }
                )
            return jsonify(ok="Message sent")
        if action == "merge":
            try:
                return jsonify(datasets.merge_live_normal())
            except ValueError as e:
                return jsonify(error=str(e)), 400
        return jsonify(error="unknown action"), 404

    @app.route("/api/net/status")
    @admin_required
    def net_status():
        s = netmon.status()
        s["dataset"] = datasets.live_info()
        return jsonify(s)

    @app.route("/api/net/packets")
    @admin_required
    def net_packets():
        if not netmon.sniffer:
            return jsonify(packets=[], last_id=0)
        a = request.args
        pk = netmon.sniffer.since(
            int(a.get("since", 0) or 0),
            min(int(a.get("limit", 300) or 300), 1000),
            a.get("host") or None,
            a.get("proto") or None,
            direction=a.get("direction") or None,
            search=a.get("search") or None
        )
        return jsonify(packets=[{k: p.get(k) for k in PKT_FIELDS} for p in pk], last_id=pk[-1]["id"] if pk else int(a.get("since", 0) or 0))

    @app.route("/api/net/host/<path:label>")
    @admin_required
    def net_host(label):
        if not netmon.sniffer:
            return jsonify(error="start the capture first"), 400
        return jsonify(netmon.sniffer.host_stats(label))
