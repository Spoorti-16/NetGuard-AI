# NetGuard: Real-Time Network IDS, Fault Diagnosis & Injection Lab
## Complete run guide

This system builds an **80-host network** (4 routers, 8 switches, 10 hosts per switch) in **Mininet**,
captures **every packet** that crosses it with a real raw-socket sniffer, classifies each connection into
**normal / fault / traffic(contention) / attack**, shows it to you live on an **animated network
diagram**, lets you **inject** traffic and attacks by pinging real hosts in the topology, schedules
**concurrent requests arriving at your own host**, and can **retrain itself automatically** as the
datasets grow. Real external machines (you, a friend) can join as real nodes alongside the simulated ones.

---

## 0. What's simulated vs what's real

| Thing | Status |
|---|---|
| 4 routers, 8 switches, 80 hosts | **Simulated**, built by Mininet + Open vSwitch inside one Linux machine (`realnet_controller.py`) - this is the same tool the earlier, smaller IDS lab used, just scaled up to this topology. |
| Packet capture of the whole topology | **Real.** A raw-socket sniffer (`sniffer.py`) opens every switch port and classifies real packets - this is not a simulation of detection, the bytes are real. |
| Your own laptop as a node | **Real**, via one physical NIC bridged into a Mininet switch (`real_hosts`), or via a VPN link routed into the topology (`gateway` / `remote_hosts`). |
| A friend's laptop | **Real**, the same way - over a VPN (recommended, works across the internet) or a NIC bridge (same LAN only). |
| 4 routers / 8 switches / 80 hosts, literally as separate physical machines | **Not attempted.** That is what Mininet is for - hardware at that scale isn't realistic for a project, and the simulation gives you the same detection and diagnosis problem at full scale, on one machine. |

---

## 1. Requirements

- Linux (Ubuntu 20.04/22.04 recommended). Mininet needs Linux and root; it will not run on WSL reliably.
- Root access (Mininet, packet capture and the control API all need it).
- Python 3.9+, and: `pip3 install -r requirements.txt`
- `sudo apt install mininet openvswitch-switch hping3 nmap`
- Optional, to add a real remote participant: [Tailscale](https://tailscale.com) or WireGuard (free, a few minutes to set up on each machine).
- If Mininet ever gets stuck between runs: `sudo mn -c`

---

## 2. Start the simulated network

```bash
cd netguard_project
sudo python3 realnet_controller.py
```

This reads `network_config.json`, builds the 80-host topology (4 routers in a ring, 8 switches, 10
hosts each), starts a small web server and DNS server inside the topology, and opens a **control API**
on `127.0.0.1:9000`. Leave this running in its own terminal.

> Do **not** also run `lab_controller.py` at the same time - both use port 9000. `lab_controller.py` is
> the older, much smaller 4-host demo kept only for reference (the **Lab** page in the nav bar); the
> 80-host system described in this guide is `realnet_controller.py` plus the **Network Map**,
> **Injection** and **Scheduler** pages.

## 3. Start the web application

```bash
sudo python3 app.py
```
Open `http://127.0.0.1:5000`. **The first account you register becomes the administrator.**

## 4. Start live capture

Go to **Network Map** (admin only) and press **Start Capture**. This opens the raw-socket sniffer on
every switch port defined in the topology (83 ports for the default size) and begins classifying
traffic in real time. You will see:
- An **animated diagram**: routers, switches and hosts laid out radially, with small dots flying
  along the links for every real flow, coloured by verdict.
- A **live packet table** you can filter by host, protocol or text.
- Counters for **normal connections saved**, **faulty flows**, and **traffic/contention rows saved**.
- An **alerts panel** for anything flagged suspicious.

---

## 5. Making yourself (and a friend) real nodes in the topology

### Option A - VPN (recommended, works over the internet)
When `gateway.enabled` is true, `realnet_controller.py` already does the Mininet-side work for you: it
creates a link between the real machine it's running on (not inside any Mininet namespace) and router
r1, gives that link the IP pair from `link_subnet`, turns on IP forwarding, and adds routes so every
Mininet router knows the way to `remote_subnet` via r1. What's left is ordinary WireGuard setup:
1. Install WireGuard on the machine running `realnet_controller.py` (the "admin machine") and on your
   friend's laptop.
2. Add your friend as a peer on the admin machine, with their `AllowedIPs` set to their own tunnel
   address (e.g. `10.99.1.2/32`, matching `remote_subnet` below).
3. On your friend's side, their WireGuard config's `AllowedIPs` must include the Mininet ranges so their
   traffic to the topology actually goes through the tunnel: `10.0.0.0/16, 10.100.0.0/16`.
4. On the **Injection** page, open **Topology config (advanced)**, press **Reload Current Config**,
   and edit the JSON:
   ```json
   "gateway": {
     "enabled": true,
     "wg_iface": "wg0",
     "link_subnet": "10.99.0.0/30",
     "remote_subnet": "10.99.1.0/24",
     "remote_hosts": [
       {"name": "friend_laptop", "ip": "10.99.1.2", "label": "My friend's laptop"}
     ]
   }
   ```
   Press **Validate & Save**. The config is checked (`netplan.build_plan`) before it's written, so a
   typo is rejected with a clear message rather than silently breaking the topology.
5. Restart capture (Network Map: **Stop**, then **Start**) so the new interface is picked up.

### Option B - a real NIC bridged into a switch (same LAN only)
If your laptop has a spare NIC (or a USB-Ethernet adapter) physically connected into the same switch
as a simulated host:
```json
"real_hosts": [
  {"name": "me_laptop", "ip": "10.0.1.250", "switch": "s1", "nic": "eth-real1", "label": "My real laptop"}
]
```
`nic` must be the real interface name on the machine running `realnet_controller.py` (check with `ip link`).

### Naming the admin host
`"admin_host": "h1_1"` in the config says which node is "you" for the purposes of the **Scheduler**
(Section 7) - every new inbound request to that host's IP gets queued and classified for you. Point it
at your real host's name (e.g. `"me_laptop"`) once you've registered one, or leave it at a simulated
host for testing without real hardware.

---

## 6. Injecting traffic (point 8 of the spec)

Open **Injection**. Every run is a real ping (or a finite number of crafted packets) between two hosts
you pick from the topology - nothing here is faked, and because it's real traffic the same capture
pipeline that watches the rest of the network sees it and classifies it automatically.

| Kind | What it does | Duration & intensity |
|---|---|---|
| **1. Normal traffic** | `ping -c N -i interval dst` between two hosts | count = duration x intensity, interval = 1/intensity |
| **2. Known attack** | One of `syn_flood, udp_flood, icmp_flood, port_scan, brute_force` via `hping3`/`nmap`, for the chosen duration | intensity sets the packet rate |
| **3. Custom traffic** | You choose protocol (icmp/tcp/udp) and port; a finite, counted packet run | same as normal, parameterised |
| **4. Unknown traffic** | The server itself picks a random, undisclosed protocol/port/rate | tests whether the model still gives a sensible verdict on a pattern it wasn't shown by name |

- If **both** hosts are simulated lab hosts (or the admin-gateway link), the injection runs immediately
  and you get back **sent / received / loss% / RTT**.
- If the **source** is a real or remote participant (your friend's laptop), nothing can be run on their
  machine from here - the panel instead shows you the **exact command** to send them. Their traffic is
  still captured and classified normally, because it crosses your monitored switch port or VPN link.

Every injection is logged (Injection page, **Injection history**) with its kind, hosts, duration,
intensity and outcome.

### What happens to the result (points 4, 5, 6 of the spec)
You do not need to do anything extra here - the **live capture pipeline already does this for every
packet**, injected or not:
- **Delivered without fault** -> a normal-connection row (`data/normal_connections.csv`), with the exact
  fields you asked for: `protocol_type, service, flag, src_bytes, dst_bytes, count, same_srv_rate,
  diff_srv_rate, duration, logged_in, is_guest_login`.
- **Not delivered** -> a fault row, with a specific reason (`host_down`, `port_closed`, `dns_fail`, etc.
  - see the Fault Diagnosis page), not a generic "faulty" label.
- **Two or more different hosts reaching the same destination within ~1.5 seconds of each other** -> a
  **traffic/contention** row (`data/traffic_dataset.csv`), separate from both of the above, exactly as
  requested: "more than 2 can't reach the same destination at the same time".

---

## 7. The Scheduler and response window (point 7 of the spec)

Open **Scheduler**. Any new conversation (a new ping, a new TCP SYN, a new UDP/DNS packet) addressed to
your **admin host**'s IP is queued here automatically (once capture is running and `admin_host`/the
gateway is set up). If two or more arrive close together, they are served **one at a time** by the
algorithm you pick:

- **fcfs** - first come, first served.
- **round_robin** - cycles fairly between the distinct sources currently waiting, so one noisy source
  can't starve the others.
- **priority** - a source already flagged elsewhere as an attacker is served first.

Each dequeued request is classified **dynamically** (not from a static table) using the same detector
as the rest of the system, and the verdict - normal / fault / attack / unknown, with confidence and
evidence - appears in the **response window** in real time. Use **Enqueue a Test Request** to see this
work even without live traffic.

---

## 8. Auto-training (point 7, closing sentence, and point 9)

On the **Injection** page, the **Auto-train** card lets you turn on automatic retraining: once
`data/normal_connections.csv` or `data/flows.csv` has grown by the configured number of new rows (40
by default) since the last training run, the matching model retrains itself in the background:
- **Model A** (NSL-KDD-style): the live normal rows are merged into the training set
  (`datasets.merge_live_normal()`), then `train_nslkdd.py` retrains Random Forest / Decision Tree / KNN.
- **Model B** (flow-based): `train_models.py` retrains directly on the growing `flows.csv`.

This also runs automatically in the background every 60 seconds while capture is active, and can be
triggered immediately after any injection, or on demand with **Check Now**.

---

## 9. Correct normal/fault/attack labelling (point 8, item 8 of the spec)

The detector names the **specific** reason for a failure instead of a generic "faulty" label - see
`detector.py`'s `FAULTS` table for the full list (DNS not found, DNS not answering, connection refused,
connection timed out, HTTP 404, HTTP 5xx, high latency/packet loss) and `flowtracker.py`'s `classify()`
for how a flow's outcome is turned into one of those reasons from real TCP/UDP/ICMP/DNS behaviour, not
guessed.

---

## 10. Correct datasets to use (point 9)

- **Model A** training/reference data: NSL-KDD (`data/kdd_train.csv`) - see the earlier fix for the
  tab-separated upload issue; use `kdd_loader.py`, which already handles that format robustly.
- **Model B** training data: your own `data/flows.csv`, built from this topology's real traffic plus
  injected scenarios - not an old public dataset, so it reflects your actual topology and your actual
  attack tools.
- **Three live datasets this project is now producing on its own**: `normal_connections.csv`,
  `traffic_dataset.csv` (contention), and the fault/attack rows visible in the **detections** table and
  **Fault Diagnosis**/**Reports** pages.

---

## 11. Page-by-page summary

| Page | Who | What it's for |
|---|---|---|
| Network Map | admin | Live animated diagram, packet table, start/stop capture, dataset counters |
| Injection | admin | Run the 4 injection kinds, see injection history, auto-train controls, topology config editor |
| Scheduler | admin (viewable: any user) | Pick the queue algorithm, watch the live response window |
| Lab (legacy 4-host) | admin | The original small Mininet-style demo - kept for reference, not the 80-host system |
| Capture | admin | Lower-level packet capture tools from the earlier IDS project |
| Live Monitor / Fault Diagnosis / Prediction / CSV Upload / Reports / Blocked IPs / Admin | - | Unchanged from the earlier IDS project - see `README.md` |

---

## 12. Safety

Everything in Sections 6-9 only ever targets hosts **named in your own `network_config.json`** -
simulated hosts, your own real host, or a remote host you and your participant explicitly registered
and consented to. Never point the known-attack or custom injection kinds at an IP you don't control.
