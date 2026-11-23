import psutil
import socket

print("Testing active connections...")
found = 0
for c in psutil.net_connections(kind='tcp'):
    if not c.raddr:
        continue
    pid = c.pid
    try:
        proc_name = psutil.Process(pid).name() if pid else "System"
    except Exception:
        proc_name = "System"
    
    rip, rport = c.raddr.ip, c.raddr.port
    lip, lport = c.laddr.ip, c.laddr.port
    print(f"[{proc_name}] {lip}:{lport} -> {rip}:{rport} ({c.status})")
    found += 1
    if found >= 6:
        break

print(f"Total connections tested: {found}")
