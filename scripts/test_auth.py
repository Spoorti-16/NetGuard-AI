import urllib.request
import urllib.parse
import http.cookiejar
import re

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Fetch register page for CSRF token
page = opener.open('http://127.0.0.1:5000/register').read().decode()
m = re.search(r'name="csrf_token" value="([^"]+)"', page)
csrf = m.group(1) if m else ""

# Register
data = urllib.parse.urlencode({
    'csrf_token': csrf,
    'username': 'Spoorti_test',
    'password': 'Password123!',
    'confirm': 'Password123!'
}).encode()
res = opener.open('http://127.0.0.1:5000/register', data=data)
print('Register status:', res.status)

# Fetch login page for CSRF token
page_l = opener.open('http://127.0.0.1:5000/login').read().decode()
m_l = re.search(r'name="csrf_token" value="([^"]+)"', page_l)
csrf_l = m_l.group(1) if m_l else ""

# Login
data2 = urllib.parse.urlencode({
    'csrf_token': csrf_l,
    'username': 'Spoorti_test',
    'password': 'Password123!'
}).encode()
res2 = opener.open('http://127.0.0.1:5000/login', data=data2)
print('Login URL:', res2.geturl())

# Check stats
res3 = opener.open('http://127.0.0.1:5000/api/my_device/stats')
print('My Device Stats:', res3.read().decode())
