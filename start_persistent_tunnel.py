import os
import re
import subprocess
import time
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "cloudflared.log")
URL_FILE = os.path.join(BASE_DIR, "public_url.txt")

# Check if an existing tunnel is still alive
if os.path.exists(URL_FILE):
    try:
        old_url = open(URL_FILE).read().strip()
        if old_url.startswith("https://"):
            with urllib.request.urlopen(old_url + "/api/chat/qr_info", timeout=3) as r:
                if r.status == 200:
                    print("EXISTING_LIVE_URL=" + old_url)
                    exit(0)
    except Exception:
        pass

# Kill any lingering cloudflared processes
try:
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/IM", "cloudflared.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.run(["pkill", "-f", "cloudflared"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
except Exception:
    pass

bin_name = "cloudflared.exe" if os.name == "nt" else "cloudflared"
log_fp = open(LOG_FILE, "w", encoding="utf-8")
proc = subprocess.Popen([bin_name, "tunnel", "--url", "http://127.0.0.1:5000"],
                        stdout=log_fp, stderr=log_fp)

found_url = None
start = time.time()
while time.time() - start < 20:
    time.sleep(1)
    if os.path.exists(LOG_FILE):
        try:
            txt = open(LOG_FILE, "r", encoding="utf-8", errors="ignore").read()
            m = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", txt)
            if m:
                found_url = m.group(0)
                break
        except Exception:
            pass

if found_url:
    with open(URL_FILE, "w", encoding="utf-8") as f:
        f.write(found_url)
    print("LIVE_PUBLIC_URL=" + found_url)
else:
    print("ERROR_URL_NOT_FOUND")
