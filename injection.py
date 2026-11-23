"""injection.py - the Injection panel's backend.

Four kinds, each with a duration (seconds) and an intensity (1 gentle .. 10 aggressive):
  normal        - deterministic ICMP ping injection (count = duration * intensity)
  known_attack  - a named attack (syn_flood / udp_flood / icmp_flood / port_scan / brute_force)
  custom        - a user-chosen protocol (icmp/tcp/udp) and port, a finite packet count
  unknown       - a randomised, undisclosed mix of protocol/port/rate - for testing whether the
                  model still gives a sensible verdict on a pattern it was not specifically shown

For traffic between two LAB hosts (or the admin's own gateway link), this module launches the
real command through the lab's control API; every packet it sends is then captured, classified
and routed into the normal / fault / traffic datasets automatically by the existing sniffer ->
flowtracker -> netmonitor pipeline (see flowtracker.py), so nothing here writes to those datasets
directly - this module only triggers the traffic and keeps a log of what was run.

For a REAL or REMOTE participant (your friend's own laptop) this module cannot run anything on
their machine - there is no agent on it. Instead it returns the exact command for that person to
type themselves; once their traffic crosses a captured switch port or the VPN gateway link, it is
captured and classified exactly the same way.
"""
import random
import time

import db
import response_engine as resp
from netplan import build_plan, host_ip, is_controllable

KINDS = ("normal", "known_attack", "custom", "unknown")
ATTACK_TYPES = ("syn_flood", "udp_flood", "icmp_flood", "port_scan", "brute_force")
PROTOS = ("icmp", "tcp", "udp")


def _plan():
    return build_plan()


def _counts(duration, intensity):
    duration = max(2, min(int(duration), 120))
    intensity = max(1, min(int(intensity), 10))
    count = max(duration * intensity, 1)
    interval = max(round(1.0 / intensity, 2), 0.05)
    return duration, intensity, count, interval


def _manual_command(kind, dst_ip, duration, intensity, attack_type, proto, port):
    duration, intensity, count, interval = _counts(duration, intensity)
    if kind == "normal":
        return f"ping -c {count} -i {interval} {dst_ip}"
    if kind == "known_attack":
        return "# a known-attack injection needs a tool you control on that machine - run it only on networks you own"
    if kind == "custom":
        flag = {"icmp": "1", "tcp": "S", "udp": "2"}.get(proto, "1")
        port_arg = f"-p {int(port)}" if proto != "icmp" and port else ""
        return f"sudo hping3 -{flag} {port_arg} -c {count} -i u{int(interval * 1e6)} {dst_ip}"
    return f"ping -c {count} {dst_ip}   # 'unknown' pattern: vary the protocol/rate yourself"


def run(kind, src, dst, duration=10, intensity=5, attack_type=None, proto="icmp", port=80, user_id=None):
    if kind not in KINDS:
        return {"error": f"kind must be one of {KINDS}"}
    plan = _plan()
    dip = host_ip(plan, dst)
    if not dip:
        return {"error": f"'{dst}' is not a known host in the topology"}
    duration, intensity, count, interval = _counts(duration, intensity)

    if not is_controllable(plan, src):
        cmd = _manual_command(kind, dip, duration, intensity, attack_type, proto, port)
        return {"manual": True, "command": cmd, "kind": kind, "src": src, "dst": dst,
                "note": f"'{src}' is a real or remote participant, so this can't be run from here - "
                        "ask them to run the command above on their own machine. Their traffic is still "
                        "captured and classified automatically once it crosses a monitored link."}

    started = time.time()
    if kind == "normal":
        r = resp.lab_call(f"/ping_test?src={src}&dst={dst}&count={count}&interval={interval}")
    elif kind == "known_attack":
        at = attack_type if attack_type in ATTACK_TYPES else "syn_flood"
        r = resp.lab_call(f"/attack?type={at}&src={src}&dst={dst}&duration={duration}&rate={int(interval * 1e6)}")
        time.sleep(min(duration, 4))              # don't hold the HTTP request open for the full attack
        r.setdefault("ok", r.get("ok"))
    elif kind == "custom":
        proto = proto if proto in PROTOS else "icmp"
        r = resp.lab_call(f"/custom_test?src={src}&dst={dst}&proto={proto}&port={int(port) if port else 0}"
                          f"&count={count}&interval={int(interval * 1000)}")
    else:  # unknown: server-chosen, undisclosed parameters - logged separately for manual review
        proto = random.choice(PROTOS)
        port = random.choice([0, 21, 23, 25, 110, 143, 3306, 8080])
        cnt = random.randint(max(5, count // 2), count * 2)
        itv_ms = random.randint(50, 1000)
        r = resp.lab_call(f"/custom_test?src={src}&dst={dst}&proto={proto}&port={port}&count={cnt}&interval={itv_ms}")
        r = dict(r, _unknown_params={"proto": proto, "port": port, "count": cnt, "interval_ms": itv_ms})

    elapsed = round(time.time() - started, 2)
    db.ex("""INSERT INTO injections(ts,kind,src,dst,duration,intensity,attack_type,proto,port,result,user_id)
             VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
          (db.now(), kind, src, dst, duration, intensity, attack_type or "", proto, port, str(r)[:500], user_id))
    try:
        import auto_train
        auto_train.maybe_retrain()
    except Exception:
        pass
    return dict(r, kind=kind, src=src, dst=dst, duration=duration, intensity=intensity, elapsed_s=elapsed)


def history(limit=50):
    return db.q("SELECT * FROM injections ORDER BY id DESC LIMIT ?", (limit,))
