"""Flask routes for: the Injection panel, the Scheduler / response window, auto-train status,
and a topology config editor (register a real or remote host, name the admin host, etc)."""
import json
import os

from flask import jsonify, render_template, request

import auto_train
import db
import injection
from config import BASE_DIR
from netmonitor import netmon
from netplan import build_plan, is_controllable

CONFIG_PATH = os.path.join(BASE_DIR, "network_config.json")


def register(app, admin_required, login_required, body):
    def plan():
        return netmon.plan or build_plan()

    # ------------------------------------------------------------------ Injection panel
    @app.route("/injection", endpoint="injection")
    @admin_required
    def injection_page():
        p = plan()
        names = [h["name"] for h in p["hosts"] + p["real_hosts"] + p["remote_hosts"]]
        return render_template("injection.html", hosts=names, admin_gw=bool(p["gateway"]),
                               kinds=injection.KINDS, attack_types=injection.ATTACK_TYPES, protos=injection.PROTOS)

    @app.route("/api/inject/options")
    @admin_required
    def inject_options():
        p = plan()
        hosts = [{"name": h["name"], "label": h.get("label", h["name"]), "ip": h["ip"], "kind": h["kind"],
                  "controllable": is_controllable(p, h["name"])} for h in p["hosts"] + p["real_hosts"] + p["remote_hosts"]]
        if p["gateway"]:
            hosts.append({"name": "admin_gw", "label": "Admin (via gateway)", "ip": p["gateway"].get("root_ip", ""),
                          "kind": "admin", "controllable": True})
        return jsonify(hosts=hosts, kinds=injection.KINDS, attack_types=injection.ATTACK_TYPES, protos=injection.PROTOS)

    @app.route("/api/inject/run", methods=["POST"])
    @admin_required
    def inject_run():
        d = body()
        if not d.get("src") or not d.get("dst"):
            return jsonify(error="choose a source and a destination host"), 400
        try:
            duration, intensity = int(d.get("duration", 10)), int(d.get("intensity", 5))
            port = int(d.get("port", 0) or 0)
        except (TypeError, ValueError):
            return jsonify(error="duration, intensity and port must be numbers"), 400
        from flask import session
        r = injection.run(d.get("kind", "normal"), d["src"], d["dst"], duration, intensity,
                          d.get("attack_type"), d.get("proto", "icmp"), port, session.get("uid"))
        return jsonify(r)

    @app.route("/api/inject/history")
    @admin_required
    def inject_history():
        return jsonify(rows=injection.history())

    # ------------------------------------------------------------------ Scheduler / response window
    @app.route("/scheduler")
    @admin_required
    def scheduler_page():
        from scheduler import ALGOS
        return render_template("scheduler.html", algos=ALGOS, algo=db.get_setting("sched_algo") or "fcfs")

    @app.route("/api/sched/status")
    @login_required
    def sched_status():
        from scheduler import scheduler
        return jsonify(scheduler.status())

    @app.route("/api/sched/algo", methods=["POST"])
    @admin_required
    def sched_algo():
        from scheduler import ALGOS
        algo = body().get("algo", "fcfs")
        if algo not in ALGOS:
            return jsonify(error=f"algo must be one of {ALGOS}"), 400
        db.set_setting("sched_algo", algo)
        return jsonify(ok=f"scheduling algorithm set to {algo}")

    @app.route("/api/sched/test_enqueue", methods=["POST"])
    @admin_required
    def sched_test_enqueue():
        """Manually enqueue a request for a demo, without needing real traffic to arrive."""
        from scheduler import scheduler
        d = body()
        iid = scheduler.enqueue(d.get("src", "demo-host"), d.get("src_ip", "0.0.0.0"), d.get("proto", "TCP"), "manual test")
        return jsonify(ok="enqueued", id=iid) if iid else jsonify(error="a request from this source was just queued - wait a moment")

    # ------------------------------------------------------------------ Auto-train
    @app.route("/api/autotrain/status")
    @admin_required
    def autotrain_status():
        return jsonify(auto_train.status())

    @app.route("/api/autotrain/run", methods=["POST"])
    @admin_required
    def autotrain_run():
        return jsonify(auto_train.maybe_retrain())

    @app.route("/api/autotrain/settings", methods=["POST"])
    @admin_required
    def autotrain_settings():
        d = body()
        try:
            every = int(d.get("retrain_every", 40))
            if not 5 <= every <= 5000:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify(error="retrain_every must be a number between 5 and 5000"), 400
        db.set_setting("auto_train", "1" if d.get("auto_train") else "0")
        db.set_setting("retrain_every", every)
        return jsonify(ok="auto-train settings saved")

    # ------------------------------------------------------------------ Topology config editor
    @app.route("/api/topology/config", methods=["GET", "POST"])
    @admin_required
    def topology_config():
        if request.method == "GET":
            with open(CONFIG_PATH) as fh:
                return jsonify(config=json.load(fh))
        d = body()
        cfg = d.get("config")
        if not isinstance(cfg, dict):
            return jsonify(error="config must be a JSON object"), 400
        try:
            build_plan(cfg)                     # validate before saving - a bad config must never be written
        except Exception as e:
            return jsonify(error=f"this config is not valid: {e}"), 400
        with open(CONFIG_PATH, "w") as fh:
            json.dump(cfg, fh, indent=2)
        return jsonify(ok="topology config saved - restart the Network Map (Stop then Start capture) to pick it up")
