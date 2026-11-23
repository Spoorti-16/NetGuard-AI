# NetGuard: Real-Time Multi-Host & Mobile Integration Guide

## 🚀 Quick Start: How to Run the Project (1 Single Command)

To run everything in NetGuard, open Ubuntu WSL / Linux terminal in the project directory and run:

```bash
sudo python3 run.py
```

This single command automatically starts all services:
1. **4 Routers & 8 Switches (Ring Topology)**: Mininet initialized with 4 core routers (`r1`..`r4`), each with 2 switches (`s1`..`s8`), and 10 dynamic host places per switch (80 places total).
2. **Dynamic Host Placement**: As real users register and authenticate, they claim the 10 places on each switch in sequence.
3. **Authentication & Universal Access**: Every participant registers and logs in with their username. All authenticated users have full access to view what an admin views.
4. **Live Packet Sniffer & Traffic Engine**: Multi-port packet monitoring and flow tracking start automatically.
5. **Cloudflare Worldwide Tunnel**: Generates a secure public URL so phones on 4G/5G mobile data or college Wi-Fi can scan the QR code and authenticate instantly.

---

### 🌐 How to Connect Devices:

| Device / Scenario | How to Connect |
|---|---|
| **Your Laptop** | Open: `http://127.0.0.1:5000/login` |
| **Phone / Friend on 4G / 5G Mobile Data** | Scan the QR code or open: `https://african-broken-grocery-petite.trycloudflare.com/login` |
| **Phone / Laptop on the Same Wi-Fi** | Open: `http://10.107.173.93:5000/login` |

> ⚠️ **Important Phone Rule**: Never type `127.0.0.1:5000` into your phone's browser (`127.0.0.1` points to the phone itself). Always scan the QR code or open the link above!

---

## 1. Network Architecture Overview

```
                      ┌──────────────────────────────────────────────┐
                      │            YOUR LAPTOP (Host 1)              │
                      │          Linux (Native or VM)                │
                      │          Admin Gateway IP: 10.99.0.1         │
                      │          Local Wi-Fi IP: 192.168.x.x         │
                      │          Tailscale IP:   100.x.y.z           │
                      └──────────────────────┬───────────────────────┘
                                             │
                       ◄══════════════ wg0 Virtual Hub ══════════════►
                                             │
         ┌───────────────────────────────────┼───────────────────────────────────┐
         │                                   │                                   │
         ▼                                   ▼                                   ▼
┌─────────────────────────────┐   ┌─────────────────────────────┐   ┌─────────────────────────────┐
│   FRIEND'S LAPTOP (Host 2)  │   │       MY PHONE (Host 3)     │   │   OTHER FRIENDS / HOSTS     │
│   Windows, Mac, or Linux    │   │   Android / iPhone (iOS)    │   │   Laptops, VMs, Tablets     │
│   Tunnel IP: 10.99.1.2      │   │   Tunnel IP: 10.99.1.5      │   │   Tunnel IPs: 10.99.1.x     │
│   Wi-Fi or Remote           │   │   Wi-Fi or 4G/5G Cellular   │   │   Wi-Fi or Remote           │
└─────────────────────────────┘   └─────────────────────────────┘   └─────────────────────────────┘
```

Inside NetGuard, **everything behaves identically**: whether a device connects across local Wi-Fi or across the internet via Tailscale, the packet sniffer (`sniffer.py`), radial SVG network map, automated intrusion detection engine, and request scheduler treat them as live nodes.

---

## 2. Updated Project Topology (`network_config.json`)

The project configuration has been updated to register your physical laptop, your friend's laptop, and your mobile phone:

```json
{
  "routers": 4,
  "switches": 8,
  "hosts_per_switch": 10,
  "named_hosts": {
    "h1_1": "Me (Admin)",
    "h2_1": "Friend-1",
    "h3_1": "Friend-2",
    "h4_1": "Friend-3"
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
        "name": "friend1_laptop",
        "ip": "10.99.1.2",
        "label": "Friend 1 Laptop"
      },
      {
        "name": "my_phone",
        "ip": "10.99.1.5",
        "label": "My Phone (Mobile)"
      }
    ]
  }
}
```

- **`admin_host: "admin_gw"`**: Assigns your physical laptop (`10.99.0.1`) as the Admin destination.
- **`friend1_laptop`**: Registered at `10.99.1.2`.
- **`my_phone`**: Registered at `10.99.1.5`.

---

## 3. Step-by-Step: Connecting Your Phone to NetGuard

You can connect an Android phone or iPhone in less than 2 minutes using the official WireGuard app.

### Step 3.1: Install the WireGuard App on Your Phone
- **Android**: Install [WireGuard from Google Play Store](https://play.google.com/store/apps/details?id=com.wireguard.android).
- **iOS (iPhone)**: Install [WireGuard from Apple App Store](https://apps.apple.com/app/wireguard/id1451159961).

---

### Step 3.2: Generate Phone Configuration
We have added a helper tool in the project root: `generate_peer_config.py`.

Run it in your Linux terminal:
```bash
python3 generate_peer_config.py my_phone 5
```

The script outputs two things:
1. The `[Peer]` block to paste into your laptop's `/etc/wireguard/wg0.conf`.
2. A ready-to-use client config file: `my_phone.conf`.

---

### Step 3.3: Add the Phone Peer to Your Laptop (`/etc/wireguard/wg0.conf`)

Open `/etc/wireguard/wg0.conf` on your laptop with `sudo`:
```ini
[Interface]
Address = 10.99.0.1/24
ListenPort = 51820
PrivateKey = <YOUR_LAPTOP_PRIVATE_KEY>

# ----------------- FRIEND 1 LAPTOP -----------------
[Peer]
PublicKey = <FRIEND_PUBLIC_KEY>
AllowedIPs = 10.99.1.2/32

# ----------------- MY PHONE (MOBILE) ----------------
[Peer]
PublicKey = <PHONE_PUBLIC_KEY_FROM_SCRIPT>
AllowedIPs = 10.99.1.5/32
```

Restart WireGuard on your laptop:
```bash
sudo wg-quick down wg0
sudo wg-quick up wg0
```

---

### Step 3.4: Configure Endpoint on the Phone (Wi-Fi vs. Tailscale)

In `my_phone.conf`, select the endpoint based on whether your phone is with you or away:

#### Mode A: Phone is WITH YOU (Same Wi-Fi)
```ini
[Interface]
PrivateKey = <PHONE_PRIVATE_KEY>
Address = 10.99.1.5/24

[Peer]
PublicKey = <YOUR_LAPTOP_PUBLIC_KEY>
# Put your laptop's local Wi-Fi IP (e.g. 192.168.1.50)
Endpoint = 192.168.1.50:51820
AllowedIPs = 10.99.0.0/16, 10.0.0.0/16, 10.100.0.0/16
PersistentKeepalive = 25
```

#### Mode B: Phone is AWAY (4G/5G Cellular Data / Tailscale)
When you are away from home or using cellular data:
1. Install [Tailscale](https://tailscale.com) on your laptop and phone.
2. Sign in to the same Tailscale account on both devices.
3. Replace the endpoint with your laptop's Tailscale IP (e.g. `100.85.120.44`):
```ini
Endpoint = 100.85.120.44:51820
```

---

### Step 3.5: Import Config into the Phone (Fast QR Code Method)

You don't need to type any keys into your phone. Install `qrencode` on your laptop:
```bash
sudo apt install -y qrencode
qrencode -t ansiutf8 < my_phone.conf
```
A QR code will display directly in your terminal:
1. Open the WireGuard app on your phone.
2. Tap the **+** button -> **Scan from QR code**.
3. Scan the terminal screen and name the tunnel `netguard`.
4. Tap the switch to **Activate**.

---

## 4. How to Run NetGuard (Two Easy Ways)

### Method 1: The All-in-One Automated Launcher (Recommended)
We built an automated master launcher [`run.py`](file:///c:/Users/SPOORTI/Downloads/netguard_project/netguard_project/run.py) that does everything with a single command:
```bash
cd netguard_project
sudo python3 run.py
```
This script automatically:
1. Resets any lingering Mininet processes (`mn -c`).
2. Activates the WireGuard VPN gateway (`wg0`) if configured.
3. Launches the SDN topology controller (`realnet_controller.py`) in the background on port `9000`.
4. Automatically activates packet capture on all switch ports and normal background traffic.
5. Starts the Flask web interface on `0.0.0.0:5000` accessible to your laptop, friend's laptop, and smartphone.

---

### Method 2: Manual Two-Terminal Launch
If you prefer running the processes in separate terminal windows:

#### Terminal 1: Start Network Topology Controller
```bash
cd netguard_project
sudo python3 realnet_controller.py
```
*Wait 30-45 seconds until you see: `Network ready. Control API on http://127.0.0.1:9000`.*

#### Terminal 2: Start Web Application & Sniffer
```bash
cd netguard_project
sudo python3 app.py
```
*Outputs: `IDS platform on http://127.0.0.1:5000`.*

---

## 5. Instant Join via QR Scanner, Worldwide Public Access & Live Inter-Host Matrix

### Why Did You See "An error occurred when loading this page" / "Loading error"?
> [!IMPORTANT]
> **Understanding the mobile error:**
> Notice in your phone's status bar: **`VoLTE`, `4G+`** (Mobile Cellular Data).
> - When your phone is using cellular data (or connected to a different Wi-Fi), private local IP addresses like `192.168.x.x` and `127.0.0.1` **cannot be reached from the public internet**.
> - **The Solution (Built Directly into NetGuard):**
>   NetGuard now includes an **Automatic Worldwide Cloudflare Quick Tunnel** ([tunnel.py](file:///c:/Users/SPOORTI/Downloads/netguard_project/netguard_project/tunnel.py)).
>   When NetGuard starts, it generates a secure, global HTTPS URL:
>   `https://<unique-name>.trycloudflare.com/chat`
>   
>   **The QR code automatically updates to this global HTTPS URL!**
>   - Works seamlessly on **4G, 5G cellular data, college Wi-Fi, and home Wi-Fi**.
>   - You can send the QR code or link to your friend anywhere in the world (via WhatsApp, email, etc.).
>   - No router setup, no port forwarding, no VPN apps required!

---

### Step 5.1: Automatic Dynamic Host Assignment & Self-Registration
The project **automatically assigns a virtual host and IP** to anyone who joins:

1. When your friend opens the link or scans the QR code on her phone/laptop:
   - She sees a clean welcome card: **"Identify Your Device to Join"**.
   - She types her name (e.g. `Pooja's Phone` or `Sarah Laptop`) and taps **Join Network**.
2. **What the project automatically does:**
   - Registers her in `db.py` as a dynamic network node.
   - Assigns her a unique virtual IP in the network topology (e.g., `10.99.1.10`, `10.99.1.11`).
   - Dynamically adds her node to the live **SVG Network Map** on the Admin screen.
   - Stores her identity in `localStorage` so she stays connected even if she refreshes.

---

### Step 5.2: Inter-Host Messaging (Send & Receive from Any Host)
Once joined, your friend can interact with the entire network:
- **Send To (Recipient) Dropdown**:
  - `Admin Laptop` (`10.99.0.1`)
  - `Lab Web Server` (`10.0.8.20`)
  - `Lab DNS Server` (`10.0.8.19`)
  - `Friend 1 Laptop` (`10.99.1.2`)
  - Any other friend or device currently connected!
- Type any message and tap **Send**.

---

### Step 5.3: "Who is Connecting With Whom" Live Matrix
Both the Admin and all participants can see who is communicating with whom in real time:
- **Live Inter-Host Matrix Table**:
  - **Host A** ⇄ **Host B**
  - **Packets / Messages Exchanged**
  - **Last Active Timestamp**
  - **Last Message Snippet**
- **Active Participants List**:
  - Displays every online device with their device type (📱 Mobile Phone / 💻 Laptop), assigned virtual IP, and online indicator!
- **SVG Network Map Animation**:
  - An animated packet particle visibly travels across the router/switch links between the two communicating nodes!
- **Packet Sniffer Table**:
  - Shows: `CHAT: [Pooja's Phone (10.99.1.10) -> Admin Laptop (10.99.0.1)]: "Hi Admin!"`
       - **Protocol**: `TCP`
       - **Info**: `CHAT: [My Phone -> Admin Laptop]: "Hello from my phone!"`
   - **SVG Network Map Animation (`/network`)**:
     - An animated cyan/blue packet particle dot appears at the phone's node.
     - The dot visibly travels across the router and switch links to the recipient node!
   - **Traffic Flow & Normal Dataset**:
     - Because it is valid TCP communication, it is cataloged as a healthy network transfer.

---

## 6. Live Demonstration Workflows with Your Phone

### Demo 1: Phone Browsing the Virtual Network
1. On your laptop, open `http://127.0.0.1:5000/network` and click **Start Capture**.
2. On your phone (with WireGuard activated), open Chrome or Safari and navigate to:
   ```
   http://10.0.8.20/
   ```
   *(This is the simulated web server on switch 8 inside Mininet!)*
3. **What to observe**:
   - The phone loads: `<h1>Lab web server</h1>`.
   - On your laptop screen, in the radial SVG map, blue animated dots travel from the **My Phone (Mobile)** node through Router `r1` -> `r4` -> `s8` to the web host.
   - In the live packet table, filter by `Host: My Phone (Mobile)`: the HTTP `GET /` and `200 OK` packets appear with the phone's IP `10.99.1.5`.

---

### Demo 2: Phone Pings & Live Anomaly Inspection
1. On your phone, install a free network utility (e.g., **Network Analyzer** or **Ping & DNS** from App Store / Play Store).
2. Ping your Admin laptop IP:
   ```
   10.99.0.1
   ```
3. **What to observe**:
   - Live yellow ICMP dots stream from `my_phone` to `admin_gw` on the Network Map.
   - Click on the `my_phone` node on the map: it shows real-time metrics (sent packets, received packets, byte counts).

---

### Demo 3: Live Inbound Request Scheduling (Scheduler)
1. Open the **Scheduler** page (`http://127.0.0.1:5000/scheduler`) on your laptop.
2. Choose scheduling algorithm: `round_robin` or `fcfs`.
3. Have your friend send requests from their laptop (`10.99.1.2`) and refresh the web page from your phone (`10.99.1.5`) at the same time.
4. **What to observe**:
   - Both devices appear in the **Response window** queue.
   - The scheduler interleaves them fairly (`Friend Laptop` -> `My Phone` -> `Friend Laptop` -> `My Phone`).
   - Dynamic classification verdicts and queue wait times are displayed in real time.

---

### Demo 4: Autonomous Attack Mitigation on Mobile Device
1. Ensure **Enable automatic blocking** is checked in **Admin -> Settings**.
2. If using a network tool on the phone that sends a rapid burst of packets (or from your friend's laptop):
   ```bash
   nmap -sS -p 1-100 10.99.0.1
   ```
3. **What to observe**:
   - Within 5 seconds, the detection engine identifies the port scan.
   - The attacking node turns red on the map.
   - An automated `iptables` DROP rule is deployed for that IP on Router `r1`.
   - Subsequent requests from that device immediately time out, while legitimate devices continue browsing unaffected.
   - The blocked IP appears in **Blocked IPs** (`/blocked`) with a self-expiring TTL countdown.

---

## 6. Quick Reference: Adding Any New Host

To add any future host (Friend 2, a tablet, or a cloud VM):
1. In `network_config.json`, add an entry under `gateway.remote_hosts`:
   ```json
   {
     "name": "friend2_laptop",
     "ip": "10.99.1.6",
     "label": "Friend 2 (MacBook)"
   }
   ```
2. Run `python3 generate_peer_config.py friend2_laptop 6`.
3. Add the generated `[Peer]` block to `/etc/wireguard/wg0.conf`.
4. Import the configuration onto the new device (Wi-Fi endpoint if local, Tailscale endpoint if remote).
