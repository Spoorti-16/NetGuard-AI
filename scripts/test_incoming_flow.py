import urllib.request
import urllib.parse
import http.cookiejar
import re
import json

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Fetch login page
page = opener.open('http://127.0.0.1:5000/login').read().decode()
m = re.search(r'name="csrf_token" value="([^"]+)"', page)
csrf = m.group(1) if m else ""

# Login as Spoorti_test
data = urllib.parse.urlencode({'csrf_token': csrf, 'username': 'Spoorti_test', 'password': 'Password123!'}).encode()
opener.open('http://127.0.0.1:5000/login', data=data)

# Check initial incoming stats
stats0 = json.loads(opener.open('http://127.0.0.1:5000/api/my_device/stats').read().decode())
print("Initial stats for Spoorti_test:", stats0)

# Send a chat message destined to Spoorti_test from another user or admin
chat_data = json.dumps({
    "sender": "Alice",
    "recipient": "Spoorti_test",
    "message": "Hello Spoorti! Packet arrival test."
}).encode()
req = urllib.request.Request(
    'http://127.0.0.1:5000/api/chat/send',
    data=chat_data,
    headers={'Content-Type': 'application/json', 'X-CSRFToken': csrf}
)
try:
    res = opener.open(req)
    print("Chat send result:", res.read().decode())
except Exception as e:
    print("Chat send error:", e)

# Check updated incoming stats
stats1 = json.loads(opener.open('http://127.0.0.1:5000/api/my_device/stats').read().decode())
print("Updated stats for Spoorti_test:", stats1)

# Check my incoming packets
pkts = json.loads(opener.open('http://127.0.0.1:5000/api/my_device/packets').read().decode())
print("Received packets count:", pkts.get("count"))
if pkts.get("packets"):
    print("Latest incoming packet:", pkts["packets"][-1])
