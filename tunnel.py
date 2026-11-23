import os
import re
import shutil
import subprocess
import sys
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URL_FILE = os.path.join(BASE_DIR, "public_url.txt")
_tunnel_proc = None
_tunnel_url = None
_lock = threading.Lock()


def _find_cloudflared():
    local_bin = os.path.join(BASE_DIR, "cloudflared.exe" if sys.platform == "win32" else "cloudflared")
    if os.path.exists(local_bin):
        return local_bin
    system_bin = shutil.which("cloudflared")
    if system_bin:
        return system_bin
    return None


def get_tunnel_url():
    global _tunnel_url
    with _lock:
        if _tunnel_url:
            return _tunnel_url
    if os.path.exists(URL_FILE):
        try:
            with open(URL_FILE, "r") as f:
                u = f.read().strip()
                if u.startswith("http"):
                    return u
        except Exception:
            pass
    return None


def start_tunnel(port=5000):
    global _tunnel_proc, _tunnel_url
    with _lock:
        if _tunnel_proc and _tunnel_proc.poll() is None:
            return _tunnel_url
    bin_path = _find_cloudflared()
    if not bin_path:
        print("[Tunnel] cloudflared not found; relying on local Wi-Fi IP.")
        return None

    def _run():
        global _tunnel_proc, _tunnel_url
        cmd = [bin_path, "tunnel", "--url", f"http://127.0.0.1:{port}"]
        try:
            _tunnel_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in iter(_tunnel_proc.stdout.readline, ""):
                m = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", line)
                if m:
                    found = m.group(0)
                    with _lock:
                        _tunnel_url = found
                    try:
                        with open(URL_FILE, "w") as f:
                            f.write(found)
                    except Exception:
                        pass
                    print(f"\n==================================================================")
                    print(f"[NetGuard Public Tunnel Active]")
                    print(f"Anyone in the world can scan or open: {found}/chat")
                    print(f"==================================================================\n")
            _tunnel_proc.wait()
        except Exception as e:
            print(f"[Tunnel Error] {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    # Wait up to 12s for initial URL
    start = time.time()
    while time.time() - start < 12:
        u = get_tunnel_url()
        if u:
            return u
        time.sleep(0.5)
    return get_tunnel_url()


def stop_tunnel():
    global _tunnel_proc
    if _tunnel_proc:
        try:
            _tunnel_proc.terminate()
        except Exception:
            pass
