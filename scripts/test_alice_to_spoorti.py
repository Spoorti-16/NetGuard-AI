import urllib.request
import urllib.parse
import http.cookiejar
import re
import json

# Session 1: Alice
cj_a = http.cookiejar.CookieJar()
op_a = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj_a))
p_a = op_a.open('http://127.0.0.1:5000/register').read().decode()
m_a = re.search(r'name="csrf_token" value="([^"]+)"', p_a)
csrf_a = m_a.group(1) if m_a else ""

# Register & Login Alice
try:
    op_a.open('http://127.0.0.1:5000/register', data=urllib.parse.urlencode({
        'csrf_token': csrf_a, 'username': 'Alice_test', 'password': 'Password123!', 'confirm': 'Password123!'
    }).encode())
except Exception:
    pass

p_al = op_a.open('http://127.0.0.1:5000/login').read().decode()
m_al = re.search(r'name="csrf_token" value="([^"]+)"', p_al)
csrf_al = m_al.group(1) if m_al else ""
op_a.open('http://127.0.0.1:5000/login', data=urllib.parse.urlencode({
    'csrf_token': csrf_al, 'username': 'Alice_test', 'password': 'Password123!'
}).encode())

# Session 2: Spoorti
cj_s = http.cookiejar.CookieJar()
op_s = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj_s))
p_s = op_s.open('http://127.0.0.1:5000/login').read().decode()
m_s = re.search(r'name="csrf_token" value="([^"]+)"', p_s)
csrf_s = m_s.group(1) if m_s else ""
op_s.open('http://127.0.0.1:5000/login', data=urllib.parse.urlencode({
    'csrf_token': csrf_s, 'username': 'Spoorti_test', 'password': 'Password123!'
}).encode())

# Alice sends message to Spoorti
req = urllib.request.Request(
    'http://127.0.0.1:5000/api/chat/send',
    data=json.dumps({"recipient": "Spoorti_test", "message": "Hi Spoorti! Packet from Alice"}).encode(),
    headers={'Content-Type': 'application/json', 'X-CSRFToken': csrf_al}
)
res = op_a.open(req)
print("Alice send response:", res.read().decode())

# Check Spoorti's stats
stats = json.loads(op_s.open('http://127.0.0.1:5000/api/my_device/stats').read().decode())
print("Spoorti's incoming stats:", stats)

# Check Spoorti's packets
pkts = json.loads(op_s.open('http://127.0.0.1:5000/api/my_device/packets').read().decode())
print("Spoorti's incoming packet list count:", pkts.get("count"))
for p in pkts.get("packets", []):
    print(" - From:", p.get("src"), "Info:", p.get("info"))
