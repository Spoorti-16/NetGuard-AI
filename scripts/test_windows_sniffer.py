import socket
import sys

host_ip = "192.168.14.60"
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((host_ip, 0))
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    s.settimeout(2.0)
    data, addr = s.recvfrom(65535)
    print("SUCCESS: Captured packet on Windows directly:", len(data), "bytes from", addr)
except Exception as e:
    print("FAILED on Windows host:", e)
