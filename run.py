#!/usr/bin/env python3
"""
run.py - All-In-One Direct Launcher for NetGuard.

Starts everything automatically in one command:
  1. Activates WireGuard (wg0) if needed.
  2. Launches the 80-host network controller (realnet_controller.py).
  3. Waits until the network is healthy on port 9000.
  4. Automatically activates live packet capture on all 84 ports.
  5. Automatically turns on background traffic.
  6. Launches the web application on http://0.0.0.0:5000.
  7. On Ctrl+C, cleanly shuts down the network and runs 'mn -c'.

Usage:
  sudo python3 run.py
"""
import atexit
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

BANNER = """
======================================================================
  NETGUARD: ALL-IN-ONE UNIFIED DIRECT LAUNCHER
======================================================================
"""

controller_proc = None
bridge_proc = None

def cleanup():
    global controller_proc, bridge_proc
    print("\n[Shutdown] Stopping NetGuard services cleanly...")
    if controller_proc and controller_proc.poll() is None:
        try:
            controller_proc.send_signal(signal.SIGINT)
            controller_proc.wait(timeout=5)
        except Exception:
            controller_proc.kill()
    if bridge_proc and bridge_proc.poll() is None:
        try:
            bridge_proc.terminate()
        except Exception:
            pass
    if os.path.exists("/mnt/c/Windows/System32/cmd.exe"):
        try:
            subprocess.run(
                ["/mnt/c/Windows/System32/cmd.exe", "/c", "wmic process where \"name like 'python%' and commandline like '%laptop_traffic_bridge%'\" delete"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception:
            pass
    try:
        from netmonitor import netmon
        if netmon.running:
            netmon.stop()
    except Exception:
        pass
    if sys.platform.startswith("linux"):
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[Shutdown] Completed cleanly.")

atexit.register(cleanup)

def free_ports():
    """Ensure ports 5000 and 9000 are completely free before launching."""
    current_pid = os.getpid()
    if sys.platform.startswith("linux"):
        for port in (5000, 9000):
            try:
                subprocess.run(["fuser", "-k", f"{port}/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            try:
                out = subprocess.check_output(["lsof", "-t", f"-i:{port}"], text=True)
                for p in out.strip().split():
                    pid_int = int(p)
                    if pid_int != current_pid:
                        try:
                            os.kill(pid_int, signal.SIGKILL)
                        except Exception:
                            pass
            except Exception:
                pass
        time.sleep(0.5)


def check_wireguard():
    cfg_path = os.path.join(BASE_DIR, "network_config.json")
    if not os.path.exists(cfg_path):
        return
    with open(cfg_path) as fh:
        cfg = json.load(fh)
    gw = cfg.get("gateway", {})
    if gw.get("enabled"):
        iface = gw.get("wg_iface", "wg0")
        print(f"[*] Gateway is enabled for interface '{iface}'. Checking status...")
        # Check if interface exists in Linux
        if sys.platform.startswith("linux"):
            res = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
            if res.returncode != 0:
                print(f"[*] Interface '{iface}' is down. Bringing it up with 'wg-quick up {iface}'...")
                up = subprocess.run(["wg-quick", "up", iface])
                if up.returncode == 0:
                    print(f"[+] WireGuard '{iface}' activated successfully.")
                else:
                    print(f"[!] Warning: Could not auto-start '{iface}'. Ensure WireGuard config exists in /etc/wireguard/{iface}.conf.")
            else:
                print(f"[+] Interface '{iface}' is already up and active.")

def start_controller():
    global controller_proc
    print("[1/3] Starting 80-host network controller (Mininet + Open vSwitch)...")
    if sys.platform.startswith("linux"):
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    log_path = os.path.join(BASE_DIR, "data", "controller_launcher.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    log_file = open(log_path, "w")
    
    controller_script = os.path.join(BASE_DIR, "realnet_controller.py")
    controller_proc = subprocess.Popen([sys.executable, controller_script], stdout=log_file, stderr=log_file)
    
    # Wait for port 9000 to be ready
    print("[2/3] Waiting for network topology and services to initialize (approx 25-35s)...")
    start_t = time.time()
    ready = False
    while time.time() - start_t < 60:
        if controller_proc.poll() is not None:
            print("[!] Controller process exited prematurely. Check data/controller_launcher.log")
            sys.exit(1)
        try:
            with urllib.request.urlopen("http://127.0.0.1:9000/status", timeout=1) as resp:
                if resp.status == 200:
                    ready = True
                    break
        except Exception:
            pass
        time.sleep(1.5)
        print(".", end="", flush=True)
        
    print()
    if not ready:
        print("[!] Timeout waiting for network controller on port 9000.")
        sys.exit(1)
        
    print("[+] Network topology ready on port 9000.")

def start_host_bridge():
    global bridge_proc
    print("[*] Launching Real-Time Laptop Host Traffic Bridge (Chrome / Wi-Fi)...")
    try:
        if os.path.exists("/mnt/c/Windows/System32/cmd.exe"):
            bridge_proc = subprocess.Popen(
                ["/mnt/c/Windows/System32/cmd.exe", "/c", "start", "/b", "python", "laptop_traffic_bridge.py"],
                cwd=BASE_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("[+] Windows Laptop Host Traffic Bridge active (monitoring Chrome & Wi-Fi).")
        elif sys.platform == "win32":
            bridge_proc = subprocess.Popen([sys.executable, "laptop_traffic_bridge.py"], cwd=BASE_DIR)
            print("[+] Laptop Host Traffic Bridge active.")
    except Exception as e:
        print(f"[!] Note on host traffic bridge: {e}")

def auto_start_services():
    print("[3/3] Auto-activating packet sniffer across laptop NIC & network...")
    try:
        from netmonitor import netmon
        res = netmon.start()
        print(f"[+] Live multi-port capture: {res.get('ok', 'active')}")
    except Exception as e:
        print(f"[!] Live capture note: {e}")
    start_host_bridge()

def main():
    print(BANNER)
    if sys.platform.startswith("linux") and os.geteuid() != 0:
        print("[!] Warning: Mininet and raw packet sniffing require root. Please run with: sudo python3 run.py\n")
        
    free_ports()
    check_wireguard()
    start_controller()
    auto_start_services()
    
    import tunnel
    pub_url = tunnel.start_tunnel(5000)

    import app as flask_app
    local_ip = flask_app._get_local_ip()

    print("\n" + "=" * 70)
    print("  NETGUARD IS FULLY RUNNING & DIRECTLY CONNECTED")
    print("=" * 70)
    print("  Local Dashboard:     http://127.0.0.1:5000  (or http://0.0.0.0:5000)")
    print(f"  Local Wi-Fi Network: http://{local_ip}:5000/chat  (Superfast for same Wi-Fi)")
    if pub_url:
        print(f"  Worldwide Web & QR:  {pub_url}/chat  (4G/5G mobile / any Wi-Fi)")
    print("  Mininet Control API: http://127.0.0.1:9000")
    print("  VPN Gateway (wg0):   10.99.0.1")
    print("  Packet Capture:      AUTOMATICALLY ACTIVE (no button clicks needed)")
    print("  Host Traffic Bridge: AUTOMATICALLY ACTIVE (Google Chrome, Wi-Fi hardware)")
    print("  Wireshark Live:      http://127.0.0.1:5000/wireshark")
    print("=" * 70)
    print("  Press Ctrl+C at any time to shut down all services cleanly.\n")
    
    # Import app and run Flask
    import app as flask_app
    flask_app.app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
