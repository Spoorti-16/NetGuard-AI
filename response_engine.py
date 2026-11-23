"""Blocking / unblocking. Real iptables runs on h3 inside Mininet via the lab API."""
import ipaddress
import json
import time
import urllib.request

import db
from config import LAB_API, SERVER_IP


def lab_call(path, timeout=10):
    try:
        return json.loads(urllib.request.urlopen(LAB_API + path, timeout=timeout).read())
    except Exception as e:
        return {"error": f"lab not reachable ({e})"}


def whitelist():
    return {x.strip() for x in db.get_setting("whitelist").split(",") if x.strip()} | {SERVER_IP, "127.0.0.1"}


def block(ip, reason="", label="", ttl_min=None):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return {"error": "invalid IP address"}
    if ip in whitelist():
        return {"error": f"{ip} is whitelisted and will not be blocked"}
    if db.q("SELECT id FROM blocked_ips WHERE ip=? AND active=1", (ip,), one=True):
        return {"error": f"{ip} is already blocked"}
    res = lab_call(f"/block?ip={ip}")
    if "error" in res:
        return res                      # rule not applied -> do not record a fake block
    ttl = int(db.get_setting("block_ttl_min")) if ttl_min is None else int(ttl_min)
    exp = time.time() + ttl * 60 if ttl > 0 else None
    prev = db.q("SELECT COUNT(*) n FROM blocked_ips WHERE ip=?", (ip,), one=True)["n"]
    db.ex("INSERT INTO blocked_ips(ip,reason,label,blocked_at,expires_at,active,block_count) VALUES(?,?,?,?,?,1,?)",
          (ip, reason, label, db.now(), exp, prev + 1))
    return {"ok": f"{ip} blocked"}


def unblock(ip):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return {"error": "invalid IP address"}
    res = lab_call(f"/unblock?ip={ip}")
    db.ex("UPDATE blocked_ips SET active=0, unblocked_at=? WHERE ip=? AND active=1", (db.now(), ip))
    return res if "error" in res else {"ok": f"{ip} unblocked"}


def expire_blocks():
    for r in db.q("SELECT ip FROM blocked_ips WHERE active=1 AND expires_at IS NOT NULL AND expires_at<?", (time.time(),)):
        unblock(r["ip"])
