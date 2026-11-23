import socket
import struct
import time

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind(('eth0', 0))
s.settimeout(3.0)
print("Listening on eth0...")
try:
    data, addr = s.recvfrom(65535)
    print("SUCCESS: Captured packet on eth0:", len(data), "bytes from addr:", addr)
except Exception as e:
    print("Timeout or error:", e)
finally:
    s.close()
