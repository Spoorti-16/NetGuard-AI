import os
import sqlite3
import time

from config import DATA_DIR, DB_PATH, DEFAULT_SETTINGS, CAPTURE_DIR

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT,
  pw_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created TEXT);
CREATE TABLE IF NOT EXISTS detections(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, source TEXT, category TEXT, label TEXT,
  confidence REAL, threat_score REAL, severity TEXT, src_ip TEXT, evidence TEXT,
  cause TEXT, fix TEXT, agreement TEXT, model TEXT, features TEXT);
CREATE INDEX IF NOT EXISTS idx_det_ts ON detections(ts);
CREATE TABLE IF NOT EXISTS windows(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, pkts_per_sec REAL, syn_rate REAL,
  bytes_per_sec REAL, category TEXT, label TEXT);
CREATE TABLE IF NOT EXISTS blocked_ips(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, reason TEXT, label TEXT, blocked_at TEXT,
  expires_at REAL, active INTEGER DEFAULT 1, block_count INTEGER DEFAULT 1, unblocked_at TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS injections(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, kind TEXT, src TEXT, dst TEXT, duration INTEGER,
  intensity INTEGER, attack_type TEXT, proto TEXT, port INTEGER, result TEXT, user_id INTEGER);
CREATE TABLE IF NOT EXISTS queue_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, src TEXT, src_ip TEXT, algo TEXT, wait_ms INTEGER,
  category TEXT, label TEXT, confidence REAL);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, sender TEXT, sender_ip TEXT,
  recipient TEXT, recipient_ip TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS dynamic_hosts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  ip TEXT UNIQUE NOT NULL,
  switch TEXT,
  router TEXT,
  port INTEGER,
  device_type TEXT DEFAULT 'Host',
  joined_at TEXT,
  last_seen TEXT);
CREATE TABLE IF NOT EXISTS auth_logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT,
  username TEXT,
  host_id TEXT,
  ip TEXT,
  status TEXT);
"""


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def conn():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    with conn() as c:
        c.executescript(SCHEMA)
        for k, v in DEFAULT_SETTINGS.items():
            c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))


def q(sql, args=(), one=False):
    with conn() as c:
        rows = c.execute(sql, args).fetchall()
    rows = [dict(r) for r in rows]
    return (rows[0] if rows else None) if one else rows


def ex(sql, args=()):
    c = conn()
    try:
        cur = c.execute(sql, args)
        c.commit()
        return cur.lastrowid
    finally:
        c.close()


def get_setting(k):
    r = q("SELECT value FROM settings WHERE key=?", (k,), one=True)
    return r["value"] if r else DEFAULT_SETTINGS.get(k, "")


def set_setting(k, v):
    ex("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))


def add_detection(source, category, label, confidence=0, threat_score=0, severity="LOW",
                  src_ip=None, evidence="", cause="", fix="", agreement=None, model="", features=""):
    return ex("""INSERT INTO detections(ts,source,category,label,confidence,threat_score,severity,
                 src_ip,evidence,cause,fix,agreement,model,features) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (now(), source, category, label, confidence, threat_score, severity, src_ip,
               evidence, cause, fix, None if agreement is None else str(agreement), model, features))


def add_message(sender, sender_ip, recipient, recipient_ip, message):
    return ex("""INSERT INTO messages(ts,sender,sender_ip,recipient,recipient_ip,message)
                 VALUES(?,?,?,?,?,?)""",
              (now(), sender, sender_ip, recipient, recipient_ip, message))


def get_messages(limit=100):
    return q("SELECT * FROM messages ORDER BY id ASC LIMIT ?", (limit,))


ALL_SLOTS = []
for s in range(1, 9):
    r = (s - 1) // 2 + 1
    for p in range(1, 11):
        ALL_SLOTS.append({
            "host_id": f"h{s}_{p}",
            "switch": f"s{s}",
            "router": f"r{r}",
            "port": p,
            "ip": f"10.0.{s}.{10 + p}"
        })


def get_host_by_username(username):
    clean_user = str(username).strip()
    row = q("SELECT * FROM dynamic_hosts WHERE LOWER(username)=LOWER(?)", (clean_user,), one=True)
    return dict(row) if row else None


def get_or_assign_host_slot(username):
    clean_user = str(username).strip()
    existing = q("SELECT * FROM dynamic_hosts WHERE LOWER(username)=LOWER(?)", (clean_user,), one=True)
    if existing:
        ex("UPDATE dynamic_hosts SET last_seen=? WHERE id=?", (now(), existing["id"]))
        res = dict(existing)
        res["last_seen"] = now()
        return res

    used_slots = {r["host_id"] for r in q("SELECT host_id FROM dynamic_hosts")}
    slot = next((s for s in ALL_SLOTS if s["host_id"] not in used_slots), None)
    if not slot:
        slot = ALL_SLOTS[0]

    ts = now()
    ex("""INSERT INTO dynamic_hosts(host_id, username, name, ip, switch, router, port, device_type, joined_at, last_seen)
          VALUES(?,?,?,?,?,?,?,?,?,?)""",
       (slot["host_id"], clean_user, clean_user, slot["ip"], slot["switch"], slot["router"], slot["port"], "Host", ts, ts))
    return {
        "host_id": slot["host_id"],
        "username": clean_user,
        "name": clean_user,
        "ip": slot["ip"],
        "switch": slot["switch"],
        "router": slot["router"],
        "port": slot["port"],
        "device_type": "Host",
        "joined_at": ts,
        "last_seen": ts
    }


def log_auth_event(username, host_id, ip, status="authenticated"):
    ex("INSERT INTO auth_logs(ts, username, host_id, ip, status) VALUES(?,?,?,?,?)",
       (now(), username, host_id, ip, status))


def reset_all_hosts():
    ex("DELETE FROM dynamic_hosts")
    ex("DELETE FROM messages")
    ex("DELETE FROM queue_log")
    ex("DELETE FROM blocked_ips")
    ex("DELETE FROM auth_logs")


def register_dynamic_host(name, device_type="phone", requested_host_id=None):
    clean_name = str(name).strip()[:40] or "Anonymous Host"
    return get_or_assign_host_slot(clean_name)


def get_dynamic_hosts():
    return q("SELECT * FROM dynamic_hosts ORDER BY id ASC")


def touch_dynamic_host(host_id):
    ex("UPDATE dynamic_hosts SET last_seen=? WHERE host_id=?", (now(), host_id))


def get_connections_matrix():
    msgs = q("SELECT * FROM messages ORDER BY id ASC")
    pairs = {}
    for m in msgs:
        s = m["sender"]
        r = m["recipient"]
        if not s or not r:
            continue
        pair_key = tuple(sorted([s, r]))
        if pair_key not in pairs:
            pairs[pair_key] = {
                "party_a": pair_key[0],
                "party_b": pair_key[1],
                "packets_exchanged": 0,
                "first_seen": m["ts"],
                "last_seen": m["ts"],
                "last_message": m["message"],
                "last_sender": s,
                "last_recipient": r
            }
        p = pairs[pair_key]
        p["packets_exchanged"] += 1
        p["last_seen"] = m["ts"]
        p["last_message"] = m["message"]
        p["last_sender"] = s
        p["last_recipient"] = r

    res = list(pairs.values())
    res.sort(key=lambda x: x["last_seen"], reverse=True)
    return res


