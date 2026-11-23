# NetGuard: Guide to Connecting Real Laptops & Live Multi-Host Demonstration

This guide provides step-by-step instructions to connect **your laptop (Host 1 / Admin)** and **your friend's laptop (Host 2 / Remote Host)** as real physical nodes into NetGuard. Once connected, real network packets (pings, web traffic, and attack simulations) will flow across the network, be captured by the raw-socket packet sniffer, and animate in real time on the interactive dashboard.

---

## 1. Network Architecture Overview

```
┌─────────────────────────────────┐                    ┌─────────────────────────────────┐
│     YOUR LAPTOP (Host 1)        │                    │   YOUR FRIEND'S LAPTOP (Host 2) │
│   Runs NetGuard (Linux/VM)      │                    │     (Windows, Mac, or Linux)    │
│   Tunnel IP: 10.99.0.1          │                    │     Tunnel IP: 10.99.1.2        │
└───────────────┬─────────────────┘                    └────────────────┬────────────────┘
                │                                                       │
                │        ◄══ WireGuard Tunnel (wg0) ══►                 │
                ▼                                                       ▼
        [ wg0 Interface ]                                    Sends real packets:
     (Sniffed by sniffer.py)                                 ping / curl / nmap
                │
                ▼
  [ Mininet Router r1 Gateway ]
  Routes packets across 80 hosts
  (10.0.0.0/16, 10.100.0.0/16)
```

- **Your Laptop**: Runs the Mininet software-defined network, raw packet sniffer, ML models, and the web interface. Acts as the `admin_host` (`admin_gw`, IP `10.99.0.1`).
- **Your Friend's Laptop**: Can run Windows, macOS, or Linux. Connects securely via a WireGuard VPN tunnel (`wg0`) with IP `10.99.1.2`.
- **Packet Visibility**: The sniffer binds directly to `wg0` with raw `AF_PACKET` sockets. Every packet sent by your friend is intercepted, decoded, and visualized live.

---

## 2. Step-by-Step Connection Setup

### Step 1: Install WireGuard

- **On Your Laptop (Linux)**:
  ```bash
  sudo apt update
  sudo apt install -y wireguard
  ```
- **On Your Friend's Laptop (Windows, macOS, or Linux)**:
  - Download and install WireGuard from [wireguard.com/install](https://www.wireguard.com/install/).

---

### Step 2: Configure the WireGuard Tunnel

#### A. Generate Keys on Your Laptop
Run the following in your terminal:
```bash
wg genkey | tee admin_private.key | wg pubkey > admin_public.key
```
Note your generated `admin_private.key` and `admin_public.key`.

#### B. Generate Keys on Your Friend's Laptop
In the WireGuard desktop app:
1. Click **Add Tunnel** -> **Add empty tunnel...**
2. WireGuard automatically generates a `PrivateKey` and `PublicKey`.
3. Copy your friend's `PublicKey`.

#### C. Create WireGuard Config on Your Laptop (`/etc/wireguard/wg0.conf`)
Open `/etc/wireguard/wg0.conf` with sudo and paste:
```ini
[Interface]
Address = 10.99.0.1/24
ListenPort = 51820
PrivateKey = <YOUR_ADMIN_PRIVATE_KEY>

[Peer]
# Your Friend's Laptop
PublicKey = <FRIEND_PUBLIC_KEY>
AllowedIPs = 10.99.1.2/32
```
Bring up the interface:
```bash
sudo wg-quick up wg0
```

#### D. Create WireGuard Config on Your Friend's Laptop
In your friend's WireGuard app, paste the following configuration:
```ini
[Interface]
PrivateKey = <FRIEND_PRIVATE_KEY>
Address = 10.99.1.2/24

[Peer]
PublicKey = <YOUR_ADMIN_PUBLIC_KEY>
# Replace with your laptop's local LAN IP (e.g. 192.168.1.50:51820) or public IP
Endpoint = <YOUR_LAPTOP_IP>:51820
# Route your laptop + all Mininet internal subnets through the tunnel
AllowedIPs = 10.99.0.0/16, 10.0.0.0/16, 10.100.0.0/16
PersistentKeepalive = 25
```
Your friend clicks **Activate** to start the tunnel.

---

### Step 3: Configure NetGuard (`network_config.json`)

Edit `network_config.json` in the project root (or navigate to **Injection -> Topology config (advanced)** in the web UI):

```json
{
  "routers": 4,
  "switches": 8,
  "hosts_per_switch": 10,
  "named_hosts": {
    "h1_1": "Simulated Node 1"
  },
  "admin_host": "admin_gw",
  "web_host": "h8_10",
  "dns_host": "h8_9",
  "attacker_host": "h1_10",
  "real_hosts": [],
  "gateway": {
    "enabled": true,
    "wg_iface": "wg0",
    "link_subnet": "10.99.0.0/30",
    "remote_subnet": "10.99.1.0/24",
    "remote_hosts": [
      {
        "name": "friend_laptop",
        "ip": "10.99.1.2",
        "label": "Friend's Laptop"
      }
    ]
  }
}
```

Key configuration points:
- `"admin_host": "admin_gw"`: Designates your machine (`10.99.0.1`) as the administrator node for the request scheduler.
- `"gateway.enabled": true`: Automatically configures Linux routing and namespaces between router `r1` and the WireGuard subnet.
- `"remote_hosts"`: Defines your friend's machine (`10.99.1.2`) as a registered entity in the topology.

---

### Step 4: Start NetGuard

1. **Terminal 1** (Start the network topology):
   ```bash
   sudo python3 realnet_controller.py
   ```
2. **Terminal 2** (Start the web platform):
   ```bash
   sudo python3 app.py
   ```
3. Open `http://127.0.0.1:5000` in your web browser.
4. Navigate to **Network Map** and click **Start Capture**.
   - Notice the status line: `sniffer.py` attaches to `wg0` alongside all internal switch ports.

---

## 3. Demonstration Procedures (Presentation Script)

Follow these 4 live demonstration scenarios to showcase multi-host real-time integration:

### Demo 1: Real Packet Streaming & Live Animated Diagram
1. Open the **Network Map** page (`/network`).
2. Point out the cyan node labeled **VPN / Friend's Laptop** on the outer edge of the SVG radial diagram.
3. Have your friend open a terminal or Command Prompt and ping your laptop:
   ```bash
   ping 10.99.0.1
   ```
4. **Observations to highlight**:
   - Small colored dots (packets) travel from the **VPN node** across router `r1` into your node.
   - Filter the packet table by `Host: Friend's Laptop` to show every live ICMP packet with timestamp, protocol, size, and TTL.
   - Click the **Friend's Laptop** node on the diagram to inspect their live statistics (sent/received packet counts and peer distribution).

---

### Demo 2: Friend Accessing Internal Simulated Servers
1. Have your friend send an HTTP request to the simulated web server on switch 8:
   ```bash
   curl http://10.0.8.20/
   ```
2. **Observations to highlight**:
   - The packet traverses multiple simulated routers: `r1` -> `r2` -> `r3` -> `r4` -> switch `s8` -> web server host.
   - The sniffer inspects the full HTTP transaction (`GET / HTTP/1.1` and `200 OK`).
   - In the **Network Map**, the **Normal-traffic dataset** counter increments: the flow completed without errors and was saved to `data/normal_connections.csv`.

---

### Demo 3: Inbound Request Scheduling (Response Window)
1. Open the **Scheduler** page (`/scheduler`) on your laptop.
2. Select an algorithm: `round_robin` or `fcfs`.
3. Have your friend send rapid connection requests to your laptop:
   ```bash
   # On friend's laptop (PowerShell or Bash loop):
   for ($i=1; $i -le 10; $i++) { curl http://10.99.0.1:5000/; Start-Sleep -Milliseconds 200 }
   ```
4. **Observations to highlight**:
   - Requests arriving at your IP are queued and processed one-by-one by the scheduler.
   - The **Response Window** displays your friend's IP (`10.99.1.2`), wait latency in milliseconds, protocol, and classification verdict (`NORMAL`).

---

### Demo 4: Live Attack Detection & Automated Firewall Mitigation
1. Open the **Live Monitor** (`/monitor`) or keep the **Network Map** open.
2. Ensure **Auto-block** is enabled in **Admin -> Settings**.
3. Have your friend simulate an intrusion attempt against your laptop:
   ```bash
   # Using Nmap from friend's machine:
   nmap -sS -p 20-100 10.99.0.1
   ```
   *(Or using hping3 if friend is on Linux: `sudo hping3 -S -p 80 -c 150 -i u2000 10.99.0.1`)*
4. **Observations to highlight**:
   - Within 5 seconds, the Live Monitor banner turns red:
     `ATTACK: PORT_SCAN (Threat Score: 75/100, Severity: HIGH)`
   - The explainability section highlights anomaly drivers (e.g., `max_ports_per_src probed multiple ports`).
   - Your friend's node on the SVG diagram displays an active red target ring.
   - NetGuard's response engine injects an active `iptables` DROP rule on router `r1`.
   - When your friend attempts to ping you again, their connection is dropped. Open **Blocked IPs** (`/blocked`) to show your friend's IP actively blocked with an expiration timer.

---

## 4. Troubleshooting & Verification

- **Check WireGuard Status**:
  ```bash
  sudo wg show
  ```
  Ensure handshake timestamps are recent and transfer counters (sent/received bytes) increment when traffic is generated.
- **Verify IP Forwarding on Host**:
  ```bash
  sysctl net.ipv4.ip_forward
  ```
  Should return `1`.
- **Reset Environment**:
  If network namespaces or interfaces get held, cleanly reset Mininet:
  ```bash
  sudo mn -c
  ```
