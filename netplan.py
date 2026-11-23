"""netplan.py - pure-Python description of the real-time network (no Mininet needed).

Default: 4 routers (ring), 8 switches (2 per router), 10 hosts per switch = 80 hosts.
  host  h{s}_{k}   IP 10.0.{s}.{10+k}/24   on switch s{s}, switch port k  (interface s{s}-eth{k})
  switch s{s} uplink to its router on port hosts_per_switch+1, router IP 10.0.{s}.1
  routers r1..rN joined in a ring with /30 links 10.100.{i}.0/30, static routes computed by BFS.
Real hosts (physical NIC) and remote hosts (WireGuard gateway) are optional extras in network_config.json.
"""
import json
import os
from collections import deque

from config import BASE_DIR

CFG_PATH = os.path.join(BASE_DIR, "network_config.json")


def load_cfg(path=CFG_PATH):
    with open(path) as fh:
        return json.load(fh)


def build_plan(cfg=None):
    cfg = cfg or load_cfg()
    R, S, H = int(cfg["routers"]), int(cfg["switches"]), int(cfg["hosts_per_switch"])
    if S % R:
        raise ValueError("switches must be a multiple of routers")
    if not (0 <= H <= 200 and 1 <= S <= 60 and 1 <= R <= 16):
        raise ValueError("network size out of range")
    per = S // R
    alias = cfg.get("named_hosts", {})
    routers = [{"name": f"r{i + 1}"} for i in range(R)]
    switches, hosts = [], []
    claimed = {}
    try:
        import db
        for dh in db.get_dynamic_hosts():
            claimed[dh["host_id"]] = dh
    except Exception:
        pass
    for j in range(S):
        sn, rn = f"s{j + 1}", f"r{j // per + 1}"
        switches.append({"name": sn, "router": rn, "subnet": f"10.0.{j + 1}.0/24", "gw": f"10.0.{j + 1}.1",
                         "uplink_port": H + 1, "router_intf": f"{rn}-{sn}"})
        for k in range(1, H + 1):
            name = f"h{j + 1}_{k}"
            dh = claimed.get(name)
            is_occupied = bool(dh)
            label = dh["username"] if dh else f"Slot {name}"
            hosts.append({"name": name, "label": label, "ip": f"10.0.{j + 1}.{10 + k}",
                          "mac": f"00:00:00:{j + 1:02x}:00:{k:02x}", "switch": sn, "router": rn,
                          "port": k, "sw_intf": f"{sn}-eth{k}", "kind": "lab",
                          "occupied": is_occupied, "username": dh["username"] if dh else None})
    # router ring
    rlinks, adj = [], {r["name"]: {} for r in routers}
    pairs = [(i, (i + 1) % R) for i in range(R)] if R > 2 else ([(0, 1)] if R == 2 else [])
    for n, (a, b) in enumerate(pairs, 1):
        ra, rb = f"r{a + 1}", f"r{b + 1}"
        ipa, ipb = f"10.100.{n}.1", f"10.100.{n}.2"
        rlinks.append({"a": ra, "b": rb, "a_intf": f"{ra}-{rb}", "b_intf": f"{rb}-{ra}", "a_ip": ipa, "b_ip": ipb,
                       "subnet": f"10.100.{n}.0/30"})
        adj[ra][rb], adj[rb][ra] = ipb, ipa            # adj[x][y] = IP of y on the x-y link
    # extra real / remote hosts
    sw_by_name = {s["name"]: s for s in switches}
    all_names = {h["name"] for h in hosts} | {r["name"] for r in routers} | {s["name"] for s in switches}
    real = []
    for i, rh in enumerate(cfg.get("real_hosts", [])):
        missing = [k for k in ("name", "ip", "switch", "nic") if k not in rh]
        if missing:
            raise ValueError(f"real_hosts[{i}] is missing: {', '.join(missing)} (needs name, ip, switch, nic)")
        if rh["name"] in all_names:
            raise ValueError(f"real_hosts[{i}]: name '{rh['name']}' already used by a lab router/switch/host")
        if rh["switch"] not in sw_by_name:
            raise ValueError(f"real_hosts[{i}]: switch '{rh['switch']}' does not exist (use one of s1..s{S}, e.g. \"s1\")")
        sw = sw_by_name[rh["switch"]]
        real.append({"name": rh["name"], "label": rh.get("label", rh["name"]), "ip": rh["ip"], "switch": sw["name"],
                     "router": sw["router"], "nic": rh["nic"], "kind": "real"})
        all_names.add(rh["name"])
    gw = cfg.get("gateway", {})
    remote, gateway = [], None
    if gw.get("enabled"):
        for k in ("wg_iface", "link_subnet", "remote_subnet"):
            if not gw.get(k):
                raise ValueError(f"gateway.enabled is true but gateway.{k} is missing")
        gateway = {"router": "r1", "iface": gw.get("wg_iface", "wg0"), "root_ip": gw["link_subnet"].split("/")[0].rsplit(".", 1)[0] + ".1",
                   "router_ip": gw["link_subnet"].split("/")[0].rsplit(".", 1)[0] + ".2",
                   "link_subnet": gw["link_subnet"], "remote_subnet": gw["remote_subnet"]}
        for i, rh in enumerate(gw.get("remote_hosts", [])):
            missing = [k for k in ("name", "ip") if k not in rh]
            if missing:
                raise ValueError(f"gateway.remote_hosts[{i}] is missing: {', '.join(missing)} (needs name, ip)")
            if rh["name"] in all_names:
                raise ValueError(f"gateway.remote_hosts[{i}]: name '{rh['name']}' is already used elsewhere")
            remote.append({"name": rh["name"], "label": rh.get("label", rh["name"]), "ip": rh["ip"], "kind": "remote", "router": "r1"})
            all_names.add(rh["name"])
        try:
            import db
            for dh in db.get_dynamic_hosts():
                if dh["host_id"] not in all_names:
                    remote.append({
                        "name": dh["host_id"],
                        "label": dh["name"],
                        "ip": dh["ip"],
                        "kind": "remote",
                        "router": "r1"
                    })
                    all_names.add(dh["host_id"])
        except Exception:
            pass
        all_names.add("admin_gw")
    if cfg.get("admin_host") and cfg["admin_host"] not in all_names:
        raise ValueError(f"admin_host '{cfg['admin_host']}' does not match any router/switch/host/real/remote name")
    # static routes: subnet -> router that owns it
    owned = {s["subnet"]: s["router"] for s in switches}
    if gateway:
        owned[gateway["remote_subnet"]] = gateway["router"]
    routes = {r["name"]: [] for r in routers}
    for r in routers:
        # BFS first hop to every other router
        first, seen, dq = {}, {r["name"]}, deque()
        for nb in adj[r["name"]]:
            first[nb] = nb
            seen.add(nb)
            dq.append(nb)
        while dq:
            x = dq.popleft()
            for nb in adj[x]:
                if nb not in seen:
                    seen.add(nb)
                    first[nb] = first[x]
                    dq.append(nb)
        for subnet, owner in owned.items():
            if owner == r["name"]:
                if gateway and subnet == gateway["remote_subnet"]:
                    routes[r["name"]].append((subnet, gateway["root_ip"]))
                continue
            if owner in first:
                routes[r["name"]].append((subnet, adj[r["name"]][first[owner]]))
    # sniff points: every host-facing switch port (+ real NICs + gateway iface + laptop NIC) -> label
    sniff = {h["sw_intf"]: h["name"] for h in hosts}
    for h in real:
        sniff[h["nic"]] = h["name"]
    if gateway:
        sniff[gateway["iface"]] = "gateway"
        sniff["ids-gw0"] = "gateway-veth"
    # Capture real traffic generated by or arriving at the laptop (Chrome, software, hardware)
    sniff["eth0"] = "Laptop Physical NIC (Chrome / Software)"
    ip_map = {h["ip"]: h["label"] for h in hosts + real + remote}
    for s in switches:
        ip_map[s["gw"]] = f"{s['router']} (gw {s['name']})"
    all_hosts = hosts + real + remote
    if gateway:
        all_hosts.append({"name": "admin_gw", "label": "Admin (via gateway)", "ip": gateway["root_ip"], "kind": "admin", "router": "r1"})
        ip_map[gateway["root_ip"]] = "Admin (via gateway)"
    admin_host = cfg.get("admin_host")
    admin_ip = next((h["ip"] for h in all_hosts if h["name"] == admin_host), None)
    active_hosts = [h for h in hosts if h.get("occupied")]
    return {"routers": routers, "switches": switches, "hosts": hosts, "active_hosts": active_hosts, "rlinks": rlinks, "real_hosts": real,
            "remote_hosts": remote, "gateway": gateway, "routes": routes, "sniff": sniff, "ip_map": ip_map,
            "web_host": cfg.get("web_host"), "dns_host": cfg.get("dns_host"), "attacker_host": cfg.get("attacker_host"),
            "admin_host": admin_host, "admin_ip": admin_ip,
            "counts": {"routers": R, "switches": S, "hosts": len(hosts), "active_hosts": len(active_hosts)}}


def host_ip(plan, name):
    hosts = plan["hosts"] + plan["real_hosts"] + plan["remote_hosts"]
    if plan.get("gateway"):
        hosts = hosts + [{"name": "admin_gw", "ip": plan["gateway"]["root_ip"]}]
    for h in hosts:
        if h["name"] == name:
            return h["ip"]
    return None


def is_controllable(plan, name):
    """A name whose commands this project can actually run: a simulated lab host, or 'admin_gw'
    (the admin's own machine, reached through the Mininet root namespace / VPN gateway link)."""
    if name == "admin_gw":
        return bool(plan["gateway"])
    return any(h["name"] == name and h["kind"] == "lab" for h in plan["hosts"])


if __name__ == "__main__":
    p = build_plan()
    print(p["counts"], "sniff ports:", len(p["sniff"]))
    for r, rt in p["routes"].items():
        print(r, len(rt), "routes", rt[:2])
