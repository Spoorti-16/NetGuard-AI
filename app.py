#!/usr/bin/env python3
"""
app.py - Flask back end for the AI-Driven Network IDS + Fault Diagnosis platform.
Run (lab features need root):  sudo python3 app.py        -> http://127.0.0.1:5000
"""
import csv
import io
import ipaddress
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from functools import wraps

import joblib
import pandas as pd
from flask import (Flask, Response, abort, flash, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db
import nslkdd_model as nsl
from kdd_loader import label_column, read_kdd
import dynamicroutes
import netroutes
import response_engine as resp
from config import BASE_DIR, CAPTURE_DIR, MODEL_DIR, NSL_DIR, SERVER_IP, secret_key
from detector import FAULTS, decide, manual_fault
from feature_extractor import FEATURE_NAMES, capture_window, extract_features, read_pcap
from monitor import monitor

os.chdir(BASE_DIR)
db.init()
app = Flask(__name__)
app.config.update(SECRET_KEY=secret_key(), MAX_CONTENT_LENGTH=30 * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

ATTACK_TYPES = ["syn_flood", "udp_flood", "icmp_flood", "port_scan", "brute_force"]
FAULT_TYPES = ["dns_down", "dns_up", "nxdomain", "web_down", "web_up", "missing_page",
               "loss", "loss_off", "drop", "drop_off"]
lab_proc = {"p": None}
train_status = {"running": False, "msg": "idle", "which": ""}
login_fail = {}


# ------------------------------------------------------------------ security helpers
def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf


@app.before_request
def csrf_protect():
    if request.method == "POST" and request.endpoint not in ("static", "api_chat_send", "api_chat_join"):
        tok = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not tok or tok != session.get("csrf"):
            abort(400, "CSRF check failed - reload the page")


@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    return r


def current_user():
    if not session.get("uid"):
        return None
    return {
        "id": session.get("uid"),
        "name": session.get("user", "User"),
        "role": "admin",  # Grants full administrative visibility to all authenticated users
        "host_id": session.get("host_id"),
        "ip": session.get("ip"),
        "switch": session.get("switch"),
        "router": session.get("router")
    }


app.jinja_env.globals["current_user"] = current_user


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("uid"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify(error="Authentication required. Please log in."), 401
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return w


def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("uid"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify(error="Authentication required. Please log in."), 401
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return w


def body():
    return request.get_json(silent=True) or {}


# ------------------------------------------------------------------ public + auth
@app.route("/")
def home():
    m = {}
    for p in (os.path.join(MODEL_DIR, "metrics.json"), os.path.join(NSL_DIR, "metrics.json")):
        if os.path.exists(p):
            m[os.path.basename(os.path.dirname(p)) or "b"] = json.load(open(p))
    return render_template("home.html", metrics=m)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p, p2 = request.form.get("password", ""), request.form.get("confirm", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", u):
            flash("Username: 3-32 letters, digits, _ . -", "err")
        elif len(p) < 8:
            flash("Password must be at least 8 characters", "err")
        elif p != p2:
            flash("Passwords do not match", "err")
        elif db.q("SELECT id FROM users WHERE LOWER(username)=LOWER(?)", (u,), one=True):
            flash("Username already exists", "err")
        else:
            first = db.q("SELECT COUNT(*) n FROM users", one=True)["n"] == 0
            db.ex("INSERT INTO users(username,email,pw_hash,role,created) VALUES(?,?,?,?,?)",
                  (u, "", generate_password_hash(p), "admin" if first else "user", db.now()))
            # Auto-assign switch host slot upon registration
            db.get_or_assign_host_slot(u)
            flash("Registered successfully! Please log in to authenticate into the network.", "ok")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        fails, until = login_fail.get(ip, (0, 0))
        if fails >= 5 and time.time() < until:
            flash("Too many attempts. Wait a minute.", "err")
            return render_template("login.html")
        u = db.q("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (request.form.get("username", "").strip(),), one=True)
        if u and check_password_hash(u["pw_hash"], request.form.get("password", "")):
            login_fail.pop(ip, None)
            session.clear()
            # Authenticate host slot in the network
            slot = db.get_or_assign_host_slot(u["username"])
            session.update(
                uid=u["id"],
                user=u["username"],
                role="admin",
                host_id=slot["host_id"],
                ip=slot["ip"],
                switch=slot.get("switch"),
                router=slot.get("router"),
                csrf=secrets.token_hex(16)
            )
            db.log_auth_event(u["username"], slot["host_id"], slot["ip"], "authenticated")
            flash(f"Authenticated as {u['username']} on {slot.get('switch')} ({slot['ip']})", "ok")
            nxt = request.args.get("next") or request.form.get("next")
            if nxt and nxt.startswith("/") and not nxt.startswith("//"):
                return redirect(nxt)
            return redirect(url_for("chat_page"))
        login_fail[ip] = (fails + 1, time.time() + 60)
        flash("Invalid username or password", "err")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out from the network.", "ok")
    return redirect(url_for("login"))
    return redirect(url_for("home"))


# ------------------------------------------------------------------ dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/stats")
@login_required
def api_stats():
    one = lambda s, a=(): db.q(s, a, one=True)["n"]
    dist = db.q("SELECT label, COUNT(*) n FROM detections WHERE category!='normal' GROUP BY label ORDER BY n DESC")
    win = db.q("SELECT ts, pkts_per_sec pps, syn_rate syn, category FROM windows ORDER BY id DESC LIMIT 60")[::-1]
    return jsonify(windows=one("SELECT COUNT(*) n FROM windows"),
                   attacks=one("SELECT COUNT(*) n FROM detections WHERE category='attack'"),
                   faults=one("SELECT COUNT(*) n FROM detections WHERE category='fault'"),
                   blocked=one("SELECT COUNT(*) n FROM blocked_ips WHERE active=1"),
                   distribution=dist, traffic=win,
                   recent=db.q("SELECT id,ts,category,label,severity,src_ip,threat_score FROM detections ORDER BY id DESC LIMIT 8"),
                   monitor_running=monitor.running)


# ------------------------------------------------------------------ lab control (Mininet)
@app.route("/lab")
@admin_required
def lab():
    return render_template("lab.html", attacks=ATTACK_TYPES, faults=FAULT_TYPES, is_root=(os.geteuid() == 0) if hasattr(os, "geteuid") else False)


@app.route("/api/lab/<action>", methods=["POST"])
@admin_required
def api_lab(action):
    d = body()
    if action == "start":
        if lab_proc["p"] and lab_proc["p"].poll() is None:
            return jsonify(error="lab already running")
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            return jsonify(error="Run the web app with sudo to start Mininet from here, or start lab_controller.py manually")
        log = open(os.path.join(BASE_DIR, "data", "lab.log"), "w")
        lab_proc["p"] = subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "realnet_controller.py" if os.path.exists(os.path.join(BASE_DIR, "realnet_controller.py")) else "lab_controller.py")], stdout=log, stderr=log)
        return jsonify(ok="Topology starting (takes a few seconds)")
    if action == "stop":
        p = lab_proc["p"]
        if p and p.poll() is None:
            p.send_signal(signal.SIGINT)
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
            subprocess.run(["mn", "-c"], capture_output=True)
        return jsonify(ok="Topology stopped")
    if action == "status":
        return jsonify(resp.lab_call("/status"))
    if action == "normal":
        return jsonify(resp.lab_call(f"/normal?on={1 if d.get('on') else 0}"))
    if action == "attack":
        if d.get("type") not in ATTACK_TYPES:
            return jsonify(error="invalid attack type"), 400
        return jsonify(resp.lab_call(f"/attack?type={d['type']}"))
    if action == "stop_attack":
        return jsonify(resp.lab_call("/stop_attack"))
    if action == "fault":
        if d.get("type") not in FAULT_TYPES:
            return jsonify(error="invalid fault type"), 400
        return jsonify(resp.lab_call(f"/fault?type={d['type']}"))
    if action == "reset":
        return jsonify(resp.lab_call("/reset"))
    abort(404)


# ------------------------------------------------------------------ capture (tshark / Wireshark)
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def safe_pcap(name):
    name = os.path.basename(name or "")
    p = os.path.join(CAPTURE_DIR, name)
    return p if name.endswith(".pcap") and os.path.isfile(p) else None


@app.route("/capture")
@admin_required
def capture():
    return render_template("capture.html", iface=db.get_setting("iface"))


@app.route("/api/capture/start", methods=["POST"])
@admin_required
def capture_start():
    d = body()
    iface, secs = str(d.get("iface", "")), min(max(int(d.get("seconds", 10)), 1), 300)
    if not IFACE_RE.match(iface):
        return jsonify(error="invalid interface name"), 400
    name = f"cap_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
    path = os.path.join(CAPTURE_DIR, name)
    try:
        subprocess.Popen(["tshark", "-q", "-i", iface, "-a", f"duration:{secs}", "-w", path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return jsonify(error="tshark not installed (sudo apt install tshark)"), 500
    return jsonify(ok=f"Capturing {secs}s to {name}", file=name)


@app.route("/api/capture/list")
@admin_required
def capture_list():
    fs = [f for f in os.listdir(CAPTURE_DIR) if f.endswith(".pcap") and not f.startswith("_")]
    return jsonify(files=[{"name": f, "kb": round(os.path.getsize(os.path.join(CAPTURE_DIR, f)) / 1024, 1)} for f in sorted(fs, reverse=True)])


@app.route("/api/capture/packets")
@admin_required
def capture_packets():
    p = safe_pcap(request.args.get("file"))
    if not p:
        return jsonify(error="file not found"), 404
    cmd = ["tshark", "-r", p, "-c", "200", "-T", "fields", "-E", "separator=|",
           "-e", "frame.number", "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst",
           "-e", "_ws.col.Protocol", "-e", "frame.len", "-e", "_ws.col.Info"]
    flt = request.args.get("filter", "").strip()
    if flt:
        cmd[3:3] = ["-Y", flt]                       # passed as one argv item, never via a shell
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as e:
        return jsonify(error=str(e)), 500
    if r.returncode != 0 and not r.stdout:
        return jsonify(error=(r.stderr or "bad display filter")[:200]), 400
    return jsonify(rows=[l.split("|") for l in r.stdout.splitlines()])


@app.route("/capture/download/<name>")
@admin_required
def capture_download(name):
    if not safe_pcap(name):
        abort(404)
    return send_from_directory(CAPTURE_DIR, os.path.basename(name), as_attachment=True)


# ------------------------------------------------------------------ live monitor
@app.route("/monitor")
@login_required
def monitor_page():
    return render_template("monitor.html")


@app.route("/api/monitor/<action>", methods=["POST", "GET"])
@login_required
def api_monitor(action):
    if action == "status":
        return jsonify(monitor.status())
    if request.method != "POST" or session.get("role") != "admin":
        return jsonify(error="admin only"), 403
    if action == "start":
        return jsonify(monitor.start())
    if action == "stop":
        return jsonify(monitor.stop())
    abort(404)


# ------------------------------------------------------------------ fault diagnosis
@app.route("/faults")
@login_required
def faults():
    summary = db.q("SELECT label, COUNT(*) n, MAX(ts) last FROM detections WHERE category='fault' GROUP BY label ORDER BY n DESC")
    rows = db.q("SELECT * FROM detections WHERE category='fault' ORDER BY id DESC LIMIT 100")
    catalogue = [{"label": k, "title": v[0], "cause": v[1], "fix": v[2]} for k, v in FAULTS.items()]
    return render_template("faults.html", summary=summary, rows=rows, catalogue=catalogue)


@app.route("/api/diagnose", methods=["POST"])
@admin_required
def api_diagnose():
    win = int(db.get_setting("window") or 5)
    path = os.path.join(CAPTURE_DIR, "_diag.pcap")
    if os.path.exists(path):
        os.remove(path)
    try:
        capture_window(db.get_setting("iface"), win, path)
    except FileNotFoundError:
        return jsonify(error="tshark not installed"), 500
    if not os.path.exists(path):
        return jsonify(error="capture failed - run as root and check the interface"), 500
    f = extract_features(read_pcap(path), win, exclude=(SERVER_IP,))
    ml = None
    if os.path.exists(os.path.join(MODEL_DIR, "rf.pkl")):
        from train_models import make_ml_predict
        ml = make_ml_predict(os.path.join(MODEL_DIR, "rf.pkl"))
    v = decide(f, ml)
    if v["category"] != "normal":
        v["detection_id"] = db.add_detection("diagnose", v["category"], v["label"], v["confidence"], v["threat_score"],
                                             v["severity"], v.get("source_ip"), v["evidence"], v["cause"], v["fix"],
                                             v.get("agreement"), "rules", json.dumps({k: f.get(k, 0) for k in FEATURE_NAMES}))
    return jsonify(v)


@app.route("/api/predict/fault", methods=["POST"])
@login_required
def api_predict_fault():
    d = body()
    try:
        v = manual_fault(str(d.get("dns", "ok")), int(d.get("http_code", 200)), float(d.get("rtt_ms", 20)),
                         float(d.get("loss_pct", 0)), str(d.get("tcp", "ok")))
    except (ValueError, TypeError):
        return jsonify(error="invalid values"), 400
    if v["category"] == "fault":
        v["detection_id"] = db.add_detection("manual", "fault", v["label"], 0.85, 20, "MEDIUM", None,
                                             v["evidence"], v["cause"], v["fix"], model="rules")
    return jsonify(v)


# ------------------------------------------------------------------ manual prediction (Model A)
@app.route("/predict")
@login_required
def predict():
    return render_template("predict.html", ready=nsl.available(), choices=nsl.choices(), presets=nsl.PRESETS)


@app.route("/api/predict", methods=["POST"])
@login_required
def api_predict():
    if not nsl.available():
        return jsonify(error="Model A is not trained yet. Admin: upload kdd_train.csv and train on the Admin page."), 400
    d = body()
    try:
        r = nsl.predict_manual(d.get("model", "rf"), d.get("fields", {}))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    r["detection_id"] = db.add_detection("manual", r["category"], r["label"], r["confidence"], r["threat_score"],
                                         r["severity"], None, "12-field manual input", model=f"NSL-{r['model']}",
                                         features=json.dumps(d.get("fields", {})))
    return jsonify(r)


# ------------------------------------------------------------------ CSV upload (batch)
@app.route("/upload")
@login_required
def upload():
    return render_template("upload.html", ready_a=nsl.available(), ready_b=os.path.exists(os.path.join(MODEL_DIR, "rf.pkl")))


@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    f, kind, model = request.files.get("file"), request.form.get("kind", "nslkdd"), request.form.get("model", "rf")
    if not f or not f.filename.lower().endswith(".csv"):
        return jsonify(error="Please choose a .csv file"), 400
    if model not in ("rf", "dt", "knn"):
        return jsonify(error="invalid model"), 400
    try:
        df = pd.read_csv(f)
    except Exception:
        return jsonify(error="could not read CSV"), 400
    if df.empty:
        return jsonify(error="CSV has no rows"), 400
    limit = min(int(request.form.get("batch", 500)), 5000)
    if kind == "nslkdd":
        if not nsl.available():
            return jsonify(error="Model A not trained"), 400
        miss = [c for c in nsl.ESSENTIAL if c not in df.columns]
        if miss:
            return jsonify(error=f"missing required columns: {', '.join(miss)}"), 400
        res = nsl.predict_dataframe(model, df, limit)
    else:
        miss = [c for c in FEATURE_NAMES if c not in df.columns]
        if miss:
            return jsonify(error=f"flow CSV missing columns: {', '.join(miss[:6])}..."), 400
        if not os.path.exists(os.path.join(MODEL_DIR, f"{model}.pkl")):
            return jsonify(error="Model B not trained"), 400
        m = joblib.load(os.path.join(MODEL_DIR, f"{model}.pkl"))
        X = df[FEATURE_NAMES].head(limit).values
        if model == "knn":
            X = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl")).transform(X)
        proba = m.predict_proba(X)
        res = []
        for p in proba:
            i = int(p.argmax())
            lab = str(m.classes_[i])
            res.append({"label": lab, "category": "normal" if lab == "normal" else ("fault" if lab in FAULTS else "attack"),
                        "confidence": round(float(p[i]), 4), "duration": "", "src_bytes": "", "dst_bytes": ""})
    attacks = [r for r in res if r["category"] != "normal"]
    for r in attacks[:200]:                       # store flagged rows (capped) for Reports
        db.add_detection("csv", r["category"], r["label"], r["confidence"], round(r["confidence"] * 100, 1),
                         "HIGH" if r["category"] == "attack" else "MEDIUM", None, f"CSV row ({f.filename})", model=model)
    avg = sum(r["confidence"] for r in res) / len(res)
    return jsonify(rows=res, total=len(res), attacks=len(attacks), avg_confidence=round(avg, 4))


# ------------------------------------------------------------------ reports
def report_query():
    where, args = ["1=1"], []
    a = request.args
    if a.get("category"):
        where.append("category=?"); args.append(a["category"])
    if a.get("label"):
        where.append("label=?"); args.append(a["label"])
    if a.get("source"):
        where.append("source=?"); args.append(a["source"])
    if a.get("ip"):
        where.append("src_ip LIKE ?"); args.append(a["ip"].strip() + "%")
    if a.get("from"):
        where.append("ts>=?"); args.append(a["from"] + " 00:00:00")
    if a.get("to"):
        where.append("ts<=?"); args.append(a["to"] + " 23:59:59")
    return " AND ".join(where), args


@app.route("/reports")
@login_required
def reports():
    w, args = report_query()
    page = max(int(request.args.get("page", 1) or 1), 1)
    total = db.q(f"SELECT COUNT(*) n FROM detections WHERE {w}", args, one=True)["n"]
    rows = db.q(f"SELECT * FROM detections WHERE {w} ORDER BY id DESC LIMIT 25 OFFSET ?", args + [(page - 1) * 25])
    stats = db.q(f"""SELECT COUNT(*) total, SUM(category='attack') attacks, SUM(category='fault') faults,
                     ROUND(AVG(confidence)*100,1) conf FROM detections WHERE {w}""", args, one=True)
    dist = db.q(f"SELECT label, COUNT(*) n FROM detections WHERE {w} GROUP BY label ORDER BY n DESC", args)
    labels = [r["label"] for r in db.q("SELECT DISTINCT label FROM detections ORDER BY label")]
    return render_template("reports.html", rows=rows, stats=stats, dist=dist, labels=labels, page=page,
                           pages=max((total + 24) // 25, 1), total=total, args=request.args)


@app.route("/reports/export.csv")
@login_required
def reports_export():
    w, args = report_query()
    rows = db.q(f"SELECT id,ts,source,category,label,confidence,threat_score,severity,src_ip,evidence,cause,fix FROM detections WHERE {w} ORDER BY id DESC LIMIT 50000", args)
    out = io.StringIO()
    wr = csv.writer(out)
    wr.writerow(["id", "time", "source", "category", "label", "confidence", "threat_score", "severity", "src_ip", "evidence", "cause", "fix"])
    for r in rows:
        wr.writerow([("'" + str(v)) if isinstance(v, str) and v[:1] in "=+-@" else v for v in r.values()])   # CSV-injection guard
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=ids_report.csv"})


@app.route("/detection/<int:did>/pdf")
@login_required
def detection_pdf(did):
    r = db.q("SELECT * FROM detections WHERE id=?", (did,), one=True)
    if not r:
        abort(404)
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        return "PDF needs reportlab: pip install reportlab", 501
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    y = 800
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Network Detection Report")
    y -= 30
    c.setFont("Helvetica", 11)
    for k in ("ts", "source", "category", "label", "severity", "threat_score", "confidence", "src_ip", "model", "agreement", "evidence", "cause", "fix"):
        text = f"{k.replace('_', ' ').title()}: {r.get(k)}"
        for i in range(0, len(text), 95):
            c.drawString(50, y, text[i:i + 95])
            y -= 16
    c.save()
    return Response(buf.getvalue(), mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename=detection_{did}.pdf"})


# ------------------------------------------------------------------ blocked IPs / response
@app.route("/blocked")
@login_required
def blocked():
    return render_template("blocked.html", active=db.q("SELECT * FROM blocked_ips WHERE active=1 ORDER BY id DESC"),
                           history=db.q("SELECT * FROM blocked_ips WHERE active=0 ORDER BY id DESC LIMIT 50"),
                           whitelist=db.get_setting("whitelist"), auto=db.get_setting("auto_block") == "1",
                           conf=db.get_setting("block_conf"))


@app.route("/api/block", methods=["POST"])
@admin_required
def api_block():
    d = body()
    return jsonify(resp.block(str(d.get("ip", "")), "manual", str(d.get("label", "manual"))))


@app.route("/api/unblock", methods=["POST"])
@admin_required
def api_unblock():
    return jsonify(resp.unblock(str(body().get("ip", ""))))


# ------------------------------------------------------------------ admin: datasets, training, users, settings
@app.route("/admin")
@admin_required
def admin():
    ld = lambda p: json.load(open(p)) if os.path.exists(p) else None
    return render_template("admin.html", users=db.q("SELECT id,username,email,role,created FROM users ORDER BY id"),
                           settings={k: db.get_setting(k) for k in ("iface", "window", "auto_block", "block_conf", "block_ttl_min", "whitelist")},
                           mb=ld(os.path.join(MODEL_DIR, "metrics.json")), ma=ld(os.path.join(NSL_DIR, "metrics.json")),
                           imgs=[f for f in ("confusion_rf.png", "confusion_dt.png", "confusion_knn.png", "feature_importance.png") if os.path.exists(os.path.join(MODEL_DIR, f))],
                           has_kdd=os.path.exists(os.path.join(BASE_DIR, "data", "kdd_train.csv")),
                           has_flows=os.path.exists(os.path.join(BASE_DIR, "data", "flows.csv")))


@app.route("/models/<path:name>")
@login_required
def model_file(name):
    if not name.endswith(".png"):
        abort(404)
    return send_from_directory(MODEL_DIR, name)


@app.route("/api/admin/upload_kdd", methods=["POST"])
@admin_required
def upload_kdd():
    f = request.files.get("file")
    if not f or not f.filename.lower().endswith(".csv"):
        return jsonify(error="choose a .csv file"), 400
    path = os.path.join(BASE_DIR, "data", "kdd_train.csv")
    f.save(path)
    try:
        df = read_kdd(path)
    except Exception as e:
        return jsonify(error=f"could not read the dataset: {e}"), 400
    lab_col = label_column(df)
    head = df.head(100)
    normal = int((head[lab_col].astype(str).str.lower().str.strip() == "normal").sum())
    return jsonify(total=len(df), columns=list(df.columns), rows=head.fillna("").astype(str).values.tolist(),
                   normal=normal, attack=len(head) - normal)


def run_training(which):
    def msg(m):
        train_status["msg"] = str(m)
    try:
        if which == "nsl":
            import train_nslkdd
            train_nslkdd.main(progress=msg)
            nsl.reset_cache()
        else:
            import train_models
            msg("Training Model B ...")
            train_models.main()
            msg("Model B trained")
    except Exception as e:
        msg(f"FAILED: {e}")
    train_status["running"] = False


@app.route("/api/admin/train/<which>", methods=["POST"])
@admin_required
def admin_train(which):
    if which not in ("nsl", "flows"):
        abort(404)
    if train_status["running"]:
        return jsonify(error="training already running")
    need = os.path.join(BASE_DIR, "data", "kdd_train.csv" if which == "nsl" else "flows.csv")
    if not os.path.exists(need):
        return jsonify(error=f"{os.path.basename(need)} not found - " + ("upload it first" if which == "nsl" else "run collect_data.py first")), 400
    train_status.update(running=True, msg="starting", which=which)
    threading.Thread(target=run_training, args=(which,), daemon=True).start()
    return jsonify(ok="training started")


@app.route("/api/admin/train_status")
@admin_required
def train_state():
    return jsonify(train_status)


@app.route("/api/admin/settings", methods=["POST"])
@admin_required
def save_settings():
    d = body()
    try:
        iface, win = str(d["iface"]), int(d["window"])
        conf, ttl = float(d["block_conf"]), int(d["block_ttl_min"])
        wl = [x.strip() for x in str(d["whitelist"]).split(",") if x.strip()]
        for x in wl:
            ipaddress.ip_address(x)
        if not IFACE_RE.match(iface) or not 2 <= win <= 60 or not 0 <= conf <= 1 or not 0 <= ttl <= 1440:
            raise ValueError
    except (KeyError, ValueError):
        return jsonify(error="invalid settings (check interface, window 2-60, confidence 0-1, ttl 0-1440, valid whitelist IPs)"), 400
    for k, v in (("iface", iface), ("window", win), ("block_conf", conf), ("block_ttl_min", ttl),
                 ("whitelist", ",".join(wl)), ("auto_block", "1" if d.get("auto_block") else "0")):
        db.set_setting(k, v)
    return jsonify(ok="settings saved")


@app.route("/api/admin/user", methods=["POST"])
@admin_required
def admin_user():
    d = body()
    uid = int(d.get("id", 0))
    if uid == session["uid"]:
        return jsonify(error="you cannot change your own account here"), 400
    if d.get("action") == "delete":
        db.ex("DELETE FROM users WHERE id=?", (uid,))
    elif d.get("action") in ("admin", "user"):
        db.ex("UPDATE users SET role=? WHERE id=?", (d["action"], uid))
    else:
        return jsonify(error="bad action"), 400
    return jsonify(ok="updated")


# ------------------------------------------------------------------ live chat & qr scanner
def _get_local_ip():
    ipconfig_cmd = "/mnt/c/Windows/System32/ipconfig.exe" if os.path.exists("/mnt/c/Windows/System32/ipconfig.exe") else ("ipconfig.exe" if sys.platform == "win32" else None)
    if ipconfig_cmd:
        try:
            out = subprocess.check_output([ipconfig_cmd], text=True, errors="ignore")
            m = re.search(r"Wireless LAN adapter Wi-Fi:.*?(?:IPv4 Address|IP Address)[.\s]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out, re.DOTALL)
            if m:
                return m.group(1).strip()
        except Exception:
            pass
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


@app.route("/chat", endpoint="chat_page")
@login_required
def chat_page():
    from netplan import build_plan
    p = build_plan()
    active_hosts = [{"name": h["name"], "label": h["label"], "ip": h["ip"]}
                    for h in p["hosts"] if h.get("occupied")]
    if p["gateway"]:
        active_hosts.insert(0, {"name": "admin_gw", "label": "Admin Laptop", "ip": p["gateway"]["root_ip"]})
    import tunnel
    pub_url = tunnel.get_tunnel_url()
    local_ip = _get_local_ip()
    local_url = f"http://{local_ip}:5000/chat"
    public_url = f"{pub_url}/chat" if pub_url else None
    chat_url = public_url if public_url else local_url
    my_h = {
        "name": session.get("user", "Host"),
        "ip": session.get("ip", "10.0.1.11"),
        "host_id": session.get("host_id", "h1_1"),
        "switch": session.get("switch", "s1"),
        "router": session.get("router", "r1")
    }
    return render_template("chat.html", hosts=active_hosts, local_ip=local_ip, chat_url=chat_url,
                           local_url=local_url, public_url=public_url, is_public=bool(pub_url),
                           my_host=my_h)


@app.route("/api/chat/join", methods=["POST"], endpoint="api_chat_join")
def api_chat_join():
    d = body() or request.form
    name = str(d.get("name", "")).strip()[:40] or "Anonymous Host"
    device_type = str(d.get("device_type", "phone")).strip()[:20]
    requested_id = str(d.get("host_id", "")).strip() or None
    host = db.register_dynamic_host(name, device_type=device_type, requested_host_id=requested_id)
    return jsonify(ok="registered", host=host)


@app.route("/api/chat/matrix")
@login_required
def api_chat_matrix():
    matrix = db.get_connections_matrix()
    dyn_hosts = db.get_dynamic_hosts()
    return jsonify(matrix=matrix, dynamic_hosts=dyn_hosts)


@app.route("/api/chat/messages")
@login_required
def api_chat_messages():
    limit = min(int(request.args.get("limit", 100)), 300)
    return jsonify(messages=db.get_messages(limit))


@app.route("/api/chat/send", methods=["POST"], endpoint="api_chat_send")
@login_required
def api_chat_send():
    d = body() or request.form
    sender = session.get("user") or str(d.get("sender", "User")).strip()[:32]
    sender_ip = session.get("ip") or "10.0.1.11"
    sender_id = session.get("host_id") or "h1_1"
    recipient = str(d.get("recipient", "admin_gw")).strip()[:32]
    msg = str(d.get("message", "")).strip()[:250]
    if not msg:
        return jsonify(error="message cannot be empty"), 400

    from netplan import build_plan
    p = build_plan()
    all_h = p["hosts"] + p["real_hosts"] + p["remote_hosts"]
    if p["gateway"]:
        all_h.append({"name": "admin_gw", "label": "Admin Laptop", "ip": p["gateway"]["root_ip"]})

    # Check if sender is registered dynamic host
    dyn_host = None
    if sender_id:
        db.touch_dynamic_host(sender_id)
        dyn_hosts = db.get_dynamic_hosts()
        dyn_host = next((dh for dh in dyn_hosts if dh["host_id"] == sender_id), None)
    if not dyn_host:
        dyn_hosts = db.get_dynamic_hosts()
        dyn_host = next((dh for dh in dyn_hosts if dh["name"].lower() == sender.lower()), None)

    if dyn_host:
        sender_ip = dyn_host["ip"]
        sender = dyn_host["name"]
    else:
        sender_host = next((h for h in all_h if h["name"] == sender or h["label"] == sender), None)
        if sender_host:
            sender_ip = sender_host["ip"]
            sender = sender_host["label"]
        else:
            sender_ip = request.remote_addr or "127.0.0.1"

    recip_host = next((h for h in all_h if h["name"] == recipient or h["label"] == recipient or h["ip"] == recipient), None)
    recip_ip = recip_host["ip"] if recip_host else "10.99.0.1"
    recip_label = recip_host["label"] if recip_host else recipient

    mid = db.add_message(sender, sender_ip, recip_label, recip_ip, msg)

    try:
        from netmonitor import netmon
        if netmon and netmon.sniffer:
            netmon.sniffer.ingest(
                data=None, hatype=1, iface="chat",
                ts=time.time(),
                custom_pkt={
                    "proto": "TCP",
                    "src_ip": sender_ip,
                    "dst_ip": recip_ip,
                    "sport": 5000,
                    "dport": 9000,
                    "length": len(msg) + 40,
                    "flags": "PSH,ACK",
                    "info": f"CHAT: [{sender} -> {recip_label}]: \"{msg[:60]}\"",
                    "payload_preview": msg[:96]
                }
            )
    except Exception:
        pass

    try:
        import urllib.parse
        resp.lab_call(f"/send?src={urllib.parse.quote(sender)}&dst={urllib.parse.quote(recip_label)}&msg={urllib.parse.quote(msg[:100])}")
    except Exception:
        pass

    return jsonify(ok="sent", id=mid, sender=sender, sender_ip=sender_ip, recipient=recip_label, recipient_ip=recip_ip, message=msg)


@app.route("/api/chat/qr_info")
def api_chat_qr_info():
    import tunnel
    pub_url = tunnel.get_tunnel_url()
    local_ip = _get_local_ip()
    local_url = f"http://{local_ip}:5000/chat"
    public_chat_url = f"{pub_url}/chat" if pub_url else None
    active_chat_url = public_chat_url or local_url
    wg_conf_path = os.path.join(BASE_DIR, "my_phone.conf")
    wg_text = open(wg_conf_path).read() if os.path.exists(wg_conf_path) else ""
    return jsonify(
        chat_url=active_chat_url,
        public_url=public_chat_url,
        local_url=local_url,
        vpn_url="http://10.99.0.1:5000/chat",
        local_ip=local_ip,
        is_public=bool(pub_url),
        wg_conf=wg_text
    )


def _matches_device(val, match_set):
    if not val:
        return False
    v_low = str(val).lower()
    for m in match_set:
        m_low = str(m).lower()
        if m_low == v_low:
            return True
        if m_low in ("laptop", "admin laptop", "gateway", "admin_gw", "host") and m_low in v_low:
            return True
    return False


def _get_user_network_identifiers(u):
    """Returns all matching identifiers (names, labels, IPs) for the user's logged-in device."""
    username = (u.get("name") or u.get("username", "")) if isinstance(u, dict) else str(u)
    names = {username, username.lower()}
    ips = set()
    slot_info = None

    if isinstance(u, dict):
        if u.get("host_id"):
            names.add(u["host_id"])
        if u.get("ip"):
            ips.add(u["ip"])

    try:
        slot_info = db.get_host_by_username(username)
        if not slot_info:
            slot_info = db.get_or_assign_host_slot(username)
    except Exception:
        slot_info = None

    if slot_info:
        slot_id = slot_info.get("host_id") or slot_info.get("slot")
        if slot_id:
            names.add(slot_id)
        if slot_info.get("ip"):
            ips.add(slot_info["ip"])

    local_ip = _get_local_ip()
    if local_ip:
        ips.add(local_ip)

    if (isinstance(u, dict) and u.get("role") == "admin") or username.lower() in ("admin", "spoorti"):
        names.update(["admin_gw", "Admin Laptop", "Admin (You)", "gateway", "Laptop", "host", "root"])
        ips.update(["10.99.0.1", "127.0.0.1", "192.168.14.60", "192.168.70.188", "192.168.64.1"])
        if local_ip:
            ips.add(local_ip)

    return {
        "username": username,
        "names": names,
        "ips": ips,
        "slot_info": slot_info
    }


@app.route("/account")
@login_required
def account_page():
    u = current_user()
    idents = _get_user_network_identifiers(u)
    return render_template(
        "account.html",
        user=u,
        username=u.get("username") if isinstance(u, dict) else str(u),
        host_slot=idents["slot_info"],
        is_admin=True
    )


@app.route("/api/my_device/stats")
@login_required
def api_my_device_stats():
    u = current_user()
    idents = _get_user_network_identifiers(u)
    names = idents["names"]
    ips = idents["ips"]

    incoming_count = 0
    outgoing_count = 0
    incoming_bytes = 0
    outgoing_bytes = 0
    recent_senders = {}
    total_packets = 0

    try:
        from netmonitor import netmon
        if netmon and netmon.sniffer:
            with netmon.sniffer.lock:
                total_packets = len(netmon.sniffer.buf)
                for p in netmon.sniffer.buf:
                    dst_match = _matches_device(p.get("dst_ip"), ips) or _matches_device(p.get("dst"), names)
                    src_match = _matches_device(p.get("src_ip"), ips) or _matches_device(p.get("src"), names)

                    if p.get("direction") == "INCOMING":
                        is_inc = True
                        is_out = False
                    elif p.get("direction") == "OUTGOING":
                        is_inc = False
                        is_out = True
                    else:
                        is_inc = dst_match and not src_match
                        is_out = src_match and not dst_match

                    if is_inc:
                        incoming_count += 1
                        incoming_bytes += p.get("length", 0)
                        sender_label = p.get("src") or p.get("src_ip") or "External / Web"
                        recent_senders[sender_label] = recent_senders.get(sender_label, 0) + 1
                    elif is_out:
                        outgoing_count += 1
                        outgoing_bytes += p.get("length", 0)
    except Exception:
        pass

    slot_info = idents["slot_info"] or {}
    return jsonify(
        username=idents["username"],
        slot=slot_info.get("host_id") or slot_info.get("slot", "Unassigned"),
        ip=slot_info.get("ip", list(ips)[0] if ips else "Unknown"),
        switch=slot_info.get("switch", "s1"),
        router=slot_info.get("router", "r1"),
        incoming_count=incoming_count,
        incoming_bytes=incoming_bytes,
        outgoing_count=outgoing_count,
        outgoing_bytes=outgoing_bytes,
        total_network_packets=total_packets,
        senders=recent_senders
    )


@app.route("/api/my_device/packets")
@login_required
def api_my_device_packets():
    u = current_user()
    idents = _get_user_network_identifiers(u)
    names = idents["names"]
    ips = idents["ips"]

    limit = min(int(request.args.get("limit", 60)), 300)
    since_id = int(request.args.get("since", 0))
    iface_filter = request.args.get("iface") or None

    incoming_count = 0
    outgoing_count = 0
    incoming_bytes = 0
    outgoing_bytes = 0
    recent_senders = {}
    packets = []

    try:
        from netmonitor import netmon
        if netmon and netmon.sniffer:
            with netmon.sniffer.lock:
                for p in netmon.sniffer.buf:
                    if iface_filter and iface_filter.lower() not in str(p.get("iface", "")).lower():
                        continue

                    dst_match = _matches_device(p.get("dst_ip"), ips) or _matches_device(p.get("dst"), names)
                    src_match = _matches_device(p.get("src_ip"), ips) or _matches_device(p.get("src"), names)

                    if p.get("direction") == "INCOMING":
                        is_inc = True
                        is_out = False
                    elif p.get("direction") == "OUTGOING":
                        is_inc = False
                        is_out = True
                    else:
                        is_inc = dst_match and not src_match
                        is_out = src_match and not dst_match

                    if is_inc:
                        incoming_count += 1
                        incoming_bytes += p.get("length", 0)
                        sender_label = p.get("src") or p.get("src_ip") or "External / Web"
                        recent_senders[sender_label] = recent_senders.get(sender_label, 0) + 1
                        if p["id"] > since_id:
                            packets.append(p)
                    elif is_out:
                        outgoing_count += 1
                        outgoing_bytes += p.get("length", 0)
    except Exception:
        pass

    top_senders = sorted(recent_senders.items(), key=lambda x: x[1], reverse=True)[:5]

    return jsonify(
        packets=packets[-limit:],
        total=incoming_count,
        count=len(packets),
        stats={
            "incoming_count": incoming_count,
            "incoming_bytes": incoming_bytes,
            "outgoing_count": outgoing_count,
            "outgoing_bytes": outgoing_bytes,
            "top_senders": top_senders
        }
    )


@app.route("/api/ingest_host_packet", methods=["POST"])
def api_ingest_host_packet():
    d = request.get_json(silent=True) or {}
    pkts = d.get("packets", [])
    if not pkts and "packet" in d:
        pkts = [d["packet"]]

    from netmonitor import netmon
    if netmon and netmon.sniffer:
        for p in pkts:
            netmon.sniffer.ingest(
                data=b"",
                custom_pkt=p,
                iface=p.get("iface", "Wi-Fi (Laptop Host)"),
                direction=p.get("direction", "INCOMING")
            )
    return jsonify(ok=True, ingested=len(pkts))


@app.route("/wireshark")
@login_required
def wireshark_page():
    return render_template("wireshark.html")


@app.route("/api/wireshark/packets")
@login_required
def api_wireshark_packets():
    from netmonitor import netmon
    if not netmon.sniffer:
        return jsonify(packets=[], last_id=0, total=0)

    a = request.args
    since_id = int(a.get("since", 0) or 0)
    limit = min(int(a.get("limit", 150) or 150), 500)
    proto = a.get("proto") or None
    direction = a.get("direction") or None
    search = a.get("search") or None
    iface = a.get("iface") or None

    pk = netmon.sniffer.since(since_id, limit=limit, proto=proto, direction=direction, search=search, iface=iface)
    return jsonify(
        packets=pk,
        last_id=pk[-1]["id"] if pk else since_id,
        count=len(pk),
        total=len(netmon.sniffer.buf)
    )


@app.route("/api/wireshark/interfaces")
@login_required
def api_wireshark_interfaces():
    from netmonitor import netmon
    counts = {}
    if netmon and netmon.sniffer:
        with netmon.sniffer.lock:
            for p in netmon.sniffer.buf:
                ifc = p.get("iface") or "Unknown"
                counts[ifc] = counts.get(ifc, 0) + 1

    standard_ifaces = [
        {"id": "Wi-Fi", "name": "Wi-Fi", "icon": "📶", "type": "Wireless NIC", "desc": "Laptop Physical Wi-Fi (Chrome & Web traffic)"},
        {"id": "Ethernet", "name": "Ethernet", "icon": "🔌", "type": "Wired NIC", "desc": "Local Area Connection (Ethernet Adapter)"},
        {"id": "Bluetooth", "name": "Bluetooth Network Connection", "icon": "📡", "type": "WPAN", "desc": "Bluetooth Personal Area Network"},
        {"id": "vEthernet", "name": "vEthernet (WSL (Hyper-V firewall))", "icon": "💻", "type": "Virtual Switch", "desc": "Hyper-V Virtual Switch to WSL"},
        {"id": "ETW", "name": "Event Tracing for Windows (ETW: etwdump)", "icon": "⚙️", "type": "Kernel Trace", "desc": "Kernel Socket & Process Telemetry"},
        {"id": "Loopback", "name": "Adapter for loopback traffic capture", "icon": "🔄", "type": "Loopback", "desc": "Localhost internal packets (127.0.0.1)"}
    ]

    for item in standard_ifaces:
        match_count = sum(v for k, v in counts.items() if item["id"].lower() in k.lower())
        item["packets"] = match_count
        item["active"] = match_count > 0

    return jsonify(interfaces=standard_ifaces)


@app.route("/api/wireshark/stats")
@login_required
def api_wireshark_stats():
    from netmonitor import netmon
    if not netmon.sniffer:
        return jsonify(running=False, total=0, incoming=0, outgoing=0, protocols={})

    with netmon.sniffer.lock:
        buf = list(netmon.sniffer.buf)

    total = len(buf)
    incoming = sum(1 for p in buf if p.get("direction") == "INCOMING")
    outgoing = sum(1 for p in buf if p.get("direction") == "OUTGOING")

    protos = {}
    for p in buf[-500:]:
        pr = p.get("proto", "OTHER")
        protos[pr] = protos.get(pr, 0) + 1

    return jsonify(
        running=netmon.sniffer.running,
        total=total,
        incoming=incoming,
        outgoing=outgoing,
        protocols=protos,
        interfaces=list(netmon.sniffer.ports.keys())
    )


@app.route("/api/export/pcap")
@login_required
def api_export_pcap():
    scope = request.args.get("scope", "device")
    limit = min(int(request.args.get("limit", 1000) or 1000), 10000)
    proto = request.args.get("proto") or None
    direction = request.args.get("direction") or None
    search = request.args.get("search") or None
    iface = request.args.get("iface") or None

    import pcap_exporter
    from netmonitor import netmon

    selected_packets = []
    if netmon and netmon.sniffer:
        if scope == "device":
            u = current_user()
            idents = _get_user_network_identifiers(u)
            names = idents["names"]
            ips = idents["ips"]
            with netmon.sniffer.lock:
                for p in netmon.sniffer.buf:
                    if iface and iface.lower() not in str(p.get("iface", "")).lower():
                        continue
                    dst_match = _matches_device(p.get("dst_ip"), ips) or _matches_device(p.get("dst"), names)
                    src_match = _matches_device(p.get("src_ip"), ips) or _matches_device(p.get("src"), names)
                    is_inc = (p.get("direction") == "INCOMING") or (dst_match and not src_match)
                    is_out = (p.get("direction") == "OUTGOING") or (src_match and not dst_match)
                    if is_inc or is_out:
                        selected_packets.append(p)
        elif scope == "incoming":
            u = current_user()
            idents = _get_user_network_identifiers(u)
            names = idents["names"]
            ips = idents["ips"]
            with netmon.sniffer.lock:
                for p in netmon.sniffer.buf:
                    if iface and iface.lower() not in str(p.get("iface", "")).lower():
                        continue
                    dst_match = _matches_device(p.get("dst_ip"), ips) or _matches_device(p.get("dst"), names)
                    src_match = _matches_device(p.get("src_ip"), ips) or _matches_device(p.get("src"), names)
                    if (p.get("direction") == "INCOMING") or (dst_match and not src_match):
                        selected_packets.append(p)
        elif scope == "wireshark":
            selected_packets = netmon.sniffer.since(0, limit=limit, proto=proto, direction=direction, search=search, iface=iface)
        else:  # "all"
            with netmon.sniffer.lock:
                selected_packets = list(netmon.sniffer.buf)
                if iface:
                    selected_packets = [p for p in selected_packets if iface.lower() in str(p.get("iface", "")).lower()]

    selected_packets = selected_packets[-limit:]
    pcap_data = pcap_exporter.packets_to_pcap(selected_packets)
    filename = f"netguard_capture_{scope}_{time.strftime('%Y%m%d_%H%M%S')}.pcap"

    return Response(
        pcap_data,
        mimetype="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Length": str(len(pcap_data))
        }
    )


netroutes.register(app, admin_required, body)
dynamicroutes.register(app, admin_required, login_required, body)


def _auto_start_pipeline():
    """Automatically starts the sniffer capture and normal background traffic
    as soon as the network controller is reachable on port 9000."""
    import urllib.request
    for _ in range(60):
        time.sleep(1)
        try:
            with urllib.request.urlopen("http://127.0.0.1:9000/status", timeout=2) as r:
                if r.status == 200:
                    break
        except Exception:
            continue
    else:
        return
    try:
        from netmonitor import netmon
        if not netmon.running:
            netmon.start()
            print("Auto-started live packet capture across laptop interfaces and network ports.")
    except Exception as e:
        print(f"Auto-start info: {e}")


threading.Thread(target=_auto_start_pipeline, daemon=True).start()


if __name__ == "__main__":
    print("IDS platform on http://127.0.0.1:5000  (first registered user becomes admin)")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
