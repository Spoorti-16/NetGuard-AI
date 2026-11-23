import socket
import struct
import time

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind(('eth0', 0))
s.settimeout(5.0)

pkts = []
start = time.time()
while time.time() - start < 6:
    try:
        data, addr = s.recvfrom(65535)
        if len(data) >= 14:
            et = struct.unpack("!H", data[12:14])[0]
            if et == 0x0800 and len(data) >= 34:
                sip = socket.inet_ntoa(data[26:30])
                dip = socket.inet_ntoa(data[30:34])
                proto = data[23]
                pkts.append((sip, dip, proto, len(data)))
    except socket.timeout:
        pass
    except Exception as e:
        print("Error:", e)
        break

print(f"Captured {len(pkts)} IPv4 packets on eth0:")
for p in pkts[:15]:
    print(f"  {p[0]} -> {p[1]} (proto {p[2]}, len {p[3]})")
