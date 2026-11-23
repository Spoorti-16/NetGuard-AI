import socket
import struct
import time

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind(('eth0', 0))
s.settimeout(5.0)

print("Sniffing eth0 for 5 seconds...")
count = 0
start = time.time()
while time.time() - start < 5 and count < 10:
    try:
        data, addr = s.recvfrom(65535)
        if len(data) >= 14:
            proto_num = struct.unpack("!H", data[12:14])[0]
            if proto_num == 0x0800 and len(data) >= 34:
                sip = socket.inet_ntoa(data[26:30])
                dip = socket.inet_ntoa(data[30:34])
                ip_proto = data[23]
                pname = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip_proto, str(ip_proto))
                print(f"Pkt #{count+1}: {pname} {sip} -> {dip} (len={len(data)})")
                count += 1
    except socket.timeout:
        break
    except Exception as e:
        print("Error:", e)
        break

print(f"Total captured on eth0: {count}")
