#!/usr/bin/env python3
"""
generate_peer_config.py - Helper tool to generate client WireGuard configs and QR codes.

Supports both:
  1. Local Wi-Fi Mode (when the person / phone is with you on the same Wi-Fi)
  2. Remote / Tailscale Mode (when the person is away, in another city, or on 4G/5G mobile data)

Usage:
  python3 generate_peer_config.py [device_name] [ip_suffix]
Examples:
  python3 generate_peer_config.py my_phone 5
  python3 generate_peer_config.py friend_laptop 2
"""
import os
import socket
import subprocess
import sys

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "192.168.1.50"
    finally:
        s.close()
    return ip

def get_tailscale_ip():
    try:
        out = subprocess.check_output(["tailscale", "ip", "-4"], text=True).strip()
        return out.splitlines()[0] if out else "100.x.y.z (run 'tailscale up' to get IP)"
    except Exception:
        return "100.x.y.z (install Tailscale for remote internet mode)"

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None

def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "my_phone"
    suffix = sys.argv[2] if len(sys.argv) > 2 else "5"
    client_ip = f"10.99.1.{suffix}"
    
    # Generate client keys using wg if available, or placeholder instructions
    priv_key = run_cmd(["wg", "genkey"])
    pub_key = run_cmd(["wg", "pubkey"], input=priv_key) if priv_key else None
    
    # Check server public key
    srv_pub = "<YOUR_SERVER_PUBLIC_KEY>"
    for p in ("/etc/wireguard/server_public.key", "server_public.key"):
        if os.path.exists(p):
            with open(p) as fh:
                srv_pub = fh.read().strip()
                break

    local_ip = get_local_ip()
    ts_ip = get_tailscale_ip()

    print("=" * 70)
    print(f" NetGuard Peer Config Generator: {name} ({client_ip})")
    print("=" * 70)
    
    print("\n--- STEP 1: ADD THIS [Peer] BLOCK TO YOUR LAPTOP'S /etc/wireguard/wg0.conf ---")
    print(f"""[Peer]
# {name}
PublicKey = {pub_key or '<CLIENT_PUBLIC_KEY>'}
AllowedIPs = {client_ip}/32""")

    client_conf = f"""[Interface]
PrivateKey = {priv_key or '<CLIENT_PRIVATE_KEY>'}
Address = {client_ip}/24

[Peer]
PublicKey = {srv_pub}
# =====================================================================
# CHOOSE YOUR ENDPOINT ACCORDING TO YOUR PREFERENCE:
# ---------------------------------------------------------------------
# Option A (LOCAL WI-FI): When device is WITH YOU on the same Wi-Fi:
Endpoint = {local_ip}:51820
#
# Option B (REMOTE / LONG DISTANCE): When device is on Mobile Data / Away:
# Endpoint = {ts_ip}:51820
# =====================================================================
AllowedIPs = 10.99.0.0/16, 10.0.0.0/16, 10.100.0.0/16
PersistentKeepalive = 25
"""

    conf_filename = f"{name}.conf"
    with open(conf_filename, "w") as fh:
        fh.write(client_conf)
        
    print(f"\n--- STEP 2: CLIENT CONFIGURATION SAVED TO: {conf_filename} ---")
    print(client_conf)
    
    print("-" * 70)
    print("HOW TO IMPORT INTO A PHONE:")
    print("  1. If 'qrencode' is installed (sudo apt install qrencode), run:")
    print(f"       qrencode -t ansiutf8 < {conf_filename}")
    print("     and scan the generated terminal QR code with the WireGuard phone app!")
    print("  2. Or simply transfer this .conf file to the phone via Bluetooth, WhatsApp, or AirDrop.")
    print("=" * 70)

if __name__ == "__main__":
    main()
