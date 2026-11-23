"""sniffer.py - admin-side packet visibility for the whole network (needs root, Linux).

Opens one raw AF_PACKET socket on every host-facing switch port (plus real NICs / the VPN gateway).
Only frames that ARRIVE at the switch from a host are kept (PACKET_OUTGOING is skipped), so every packet a host sends
is recorded exactly once - no duplicates from the receiving port.

By default only HEADER metadata is stored (addresses, ports, protocol, size, flags, DNS name, HTTP request line).
A short payload preview is stored only when payload_preview is switched on, which participants must agree to.
"""
import socket
import struct
import threading
import time
from collections import deque

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
ARPHRD_NONE = 65534
TCP_FLAGS = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")]
ICMP_NAMES = {0: "Echo reply", 3: "Destination unreachable", 8: "Echo request", 11: "Time exceeded"}


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _ip(b):
    return socket.inet_ntoa(b)


def _dns_name(data, off=12):
    labels, n = [], 0
    while off < len(data) and n < 40:
        ln = data[off]
        if ln == 0 or ln >= 0xC0:
            break
        labels.append(data[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += ln + 1
        n += 1
    return ".".join(labels)


def preview(payload, n=96):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:n])


def format_hex_dump(data, max_bytes=256):
    """Formats raw frame bytes into standard Wireshark hex + ASCII view."""
    lines = []
    chunk = data[:max_bytes]
    for i in range(0, len(chunk), 16):
        block = chunk[i:i+16]
        hex_bytes = " ".join(f"{b:02x}" for b in block)
        if len(block) > 8:
            hex_part = f"{' '.join(f'{b:02x}' for b in block[:8])}  {' '.join(f'{b:02x}' for b in block[8:])}"
        else:
            hex_part = hex_bytes
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in block)
        lines.append(f"{i:04x}   {hex_part:<49}   {ascii_part}")
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} more bytes)")
    return "\n".join(lines)


def extract_tls_sni(data):
    """Extracts Server Name Indication (SNI) from TLS Client Hello (e.g. google.com from Chrome)."""
    try:
        if len(data) < 43 or data[0] != 0x16:
            return None
        if data[5] != 0x01:
            return None
        pos = 43
        if len(data) <= pos:
            return None
        session_id_len = data[pos]
        pos += 1 + session_id_len
        if len(data) <= pos + 2:
            return None
        cipher_suites_len = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2 + cipher_suites_len
        if len(data) <= pos + 1:
            return None
        compression_methods_len = data[pos]
        pos += 1 + compression_methods_len
        if len(data) <= pos + 2:
            return None
        extensions_len = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2
        end_ext = min(pos + extensions_len, len(data))
        while pos + 4 <= end_ext:
            ext_type, ext_len = struct.unpack("!HH", data[pos:pos+4])
            pos += 4
            if ext_type == 0:  # SNI extension
                if pos + 5 <= len(data):
                    name_len = struct.unpack("!H", data[pos+3:pos+5])[0]
                    return data[pos+5:pos+5+name_len].decode("ascii", "replace")
            pos += ext_len
    except Exception:
        pass
    return None


def parse_frame(data, hatype=1):
    """Parse one frame. Returns a dict or None (IPv6 / unsupported). Pure function - unit-testable."""
    p = {"src_mac": "", "dst_mac": "", "hex_dump": format_hex_dump(data)}
    off = 0
    if hatype != ARPHRD_NONE:
        if len(data) < 14:
            return None
        p["dst_mac"], p["src_mac"] = _mac(data[0:6]), _mac(data[6:12])
        et = struct.unpack("!H", data[12:14])[0]
        p["ethertype"] = f"0x{et:04x}"
        off = 14
        if et == 0x8100 and len(data) >= 18:
            et = struct.unpack("!H", data[16:18])[0]
            off = 18
        if et == 0x0806 and len(data) >= off + 28:
            op = struct.unpack("!H", data[off + 6:off + 8])[0]
            sip, tip = _ip(data[off + 14:off + 18]), _ip(data[off + 24:off + 28])
            p.update(proto="ARP", src_ip=sip, dst_ip=tip, sport=0, dport=0, length=len(data), flags="", ttl=0,
                     info=(f"Who has {tip}? Tell {sip}" if op == 1 else f"{sip} is at {p['src_mac']}"))
            return p
        if et != 0x0800:
            return None
    if len(data) < off + 20:
        return None
    ihl = (data[off] & 0x0F) * 4
    tot = struct.unpack("!H", data[off + 2:off + 4])[0]
    ttl, proto = data[off + 8], data[off + 9]
    ip_id = struct.unpack("!H", data[off + 4:off + 6])[0]
    p.update(src_ip=_ip(data[off + 12:off + 16]), dst_ip=_ip(data[off + 16:off + 20]), ttl=ttl,
             ihl=ihl, ip_id=f"0x{ip_id:04x}", length=tot or len(data) - off, sport=0, dport=0, flags="",
             info="", proto=str(proto), tcp_flags=0, payload=b"", dns_qr=None, dns_rcode=None,
             http_code=0, icmp_type=None, seq=0, ack=0, window=0, paylen=0)
    t = off + ihl
    frag = struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF
    if frag:
        p["info"] = "IP fragment"
        return p
    if proto == 6 and len(data) >= t + 20:
        sport, dport, seq, ack = struct.unpack("!HHII", data[t:t + 12])
        doff = (data[t + 12] >> 4) * 4
        fl = data[t + 13]
        window = struct.unpack("!H", data[t + 14:t + 16])[0]
        pl = data[t + doff:off + tot] if tot else data[t + doff:]
        names = [n for bit, n in TCP_FLAGS if fl & bit]
        p.update(proto="TCP", sport=sport, dport=dport, tcp_flags=fl, flags=",".join(names), seq=seq, ack=ack,
                 window=window, payload=pl, paylen=len(pl))
        info = f"{sport} \u2192 {dport} [{','.join(names)}] Seq={seq} Ack={ack} Len={len(pl)}"
        if sport == 443 or dport == 443 or (len(pl) >= 5 and pl[0] == 0x16 and pl[1] == 0x03):
            sni = extract_tls_sni(pl)
            if sni:
                p.update(proto="TLS", info=f"TLSv1.3 Client Hello (SNI: {sni})")
            else:
                p.update(proto="TLS", info=f"TLS Application Data {sport} \u2192 {dport} len={len(pl)}")
        elif pl[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE"):
            line = pl.split(b"\r\n", 1)[0][:90].decode("ascii", "replace")
            p.update(proto="HTTP", info="HTTP " + line)
        elif pl[:5] == b"HTTP/":
            line = pl.split(b"\r\n", 1)[0][:60].decode("ascii", "replace")
            p.update(proto="HTTP", info=line)
            try:
                p["http_code"] = int(line.split()[1])
            except (IndexError, ValueError):
                pass
        else:
            p["info"] = info
    elif proto == 17 and len(data) >= t + 8:
        sport, dport = struct.unpack("!HH", data[t:t + 4])
        pl = data[t + 8:]
        p.update(proto="UDP", sport=sport, dport=dport, payload=pl, paylen=len(pl))
        p["info"] = f"{sport} \u2192 {dport} len={len(pl)}"
        if (sport == 53 or dport == 53) and len(pl) >= 12:
            flags = struct.unpack("!H", pl[2:4])[0]
            qr, rcode = (flags >> 15) & 1, flags & 0xF
            p.update(proto="DNS", dns_qr=qr, dns_rcode=rcode)
            name = _dns_name(pl)
            p["info"] = f"DNS query {name}" if not qr else f"DNS response {name} rcode={rcode}" + (" (NXDOMAIN)" if rcode == 3 else "")
        elif sport == 443 or dport == 443:
            p.update(proto="QUIC", info=f"QUIC / HTTP3 {sport} \u2192 {dport} len={len(pl)}")
    elif proto == 1 and len(data) >= t + 4:
        ty = data[t]
        p.update(proto="ICMP", icmp_type=ty, info=ICMP_NAMES.get(ty, f"ICMP type {ty}"))
    return p


class Sniffer:
    def __init__(self, sniff_ports, ip_map, maxlen=30000):
        self.ports, self.ip_map = dict(sniff_ports), ip_map
        self.buf = deque(maxlen=maxlen)
        self.counter = 0
        self.socks, self.errors = {}, []
        self.running = False
        self.payload_preview = False
        self.listeners = []          # callables(packet_dict) run in the sniffer thread
        self.thread = None
        self.lock = threading.Lock()

    def name(self, ip):
        if ip in self.ip_map:
            return self.ip_map[ip]
        try:
            import db
            for dh in db.get_dynamic_hosts():
                if dh["ip"] == ip:
                    self.ip_map[ip] = dh["name"]
                    return dh["name"]
        except Exception:
            pass
        return ip

    def start(self):
        if self.running:
            return
        self.socks, self.errors = {}, []
        if "eth0" not in self.ports:
            self.ports["eth0"] = "Laptop Physical NIC (Chrome / Software)"
        for iface in self.ports:
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
                s.bind((iface, 0))
                s.setblocking(False)
                self.socks[s] = iface
            except OSError as e:
                self.errors.append(f"{iface}: {e.strerror or e}")
        if not self.socks:
            raise RuntimeError("no capture interfaces could be opened (is the network running? are you root?) " + "; ".join(self.errors[:3]))
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        for s in self.socks:
            s.close()
        self.socks = {}

    def _loop(self):
        import select
        while self.running:
            try:
                ready, _, _ = select.select(list(self.socks), [], [], 0.5)
            except (OSError, ValueError):
                break
            for s in ready:
                for _ in range(200):               # drain the socket
                    try:
                        data, addr = s.recvfrom(65535)
                    except BlockingIOError:
                        break
                    except OSError:
                        break
                    iface_name = self.socks.get(s, "?")
                    if addr[2] == PACKET_OUTGOING and iface_name != "eth0":
                        continue
                    direction = "OUTGOING" if addr[2] == PACKET_OUTGOING else "INCOMING"
                    self.ingest(data, addr[3], iface_name, direction=direction)

    def ingest(self, data, hatype=1, iface="?", ts=None, custom_pkt=None, direction="INCOMING"):
        t = ts or time.time()
        time_str = time.strftime("%H:%M:%S", time.localtime(t)) + f".{int((t % 1) * 1000):03d}"
        if custom_pkt is not None:
            p = dict(custom_pkt)
            self.counter += 1
            pkt_dir = p.get("direction") or direction
            pkt_iface = p.get("iface") or iface
            pkt_src = p.get("src") or self.name(p.get("src_ip", ""))
            pkt_dst = p.get("dst") or self.name(p.get("dst_ip", ""))
            p.update(id=self.counter, ts=t, time_str=time_str, iface=pkt_iface, direction=pkt_dir,
                     src=pkt_src, dst=pkt_dst, retrans=False)
            with self.lock:
                self.buf.append(p)
            for fn in self.listeners:
                try:
                    fn(p, b"")
                except Exception:
                    pass
            return p
        p = parse_frame(data, hatype)
        if not p:
            return None
        if iface == "eth0" and (p.get("sport") in (5000, 9000) or p.get("dport") in (5000, 9000)):
            return None
        self.counter += 1
        p.update(id=self.counter, ts=t, time_str=time_str, iface=iface, direction=direction,
                 src=self.name(p["src_ip"]), dst=self.name(p["dst_ip"]), retrans=False)
        pl = p.pop("payload", b"")
        p["payload_preview"] = preview(pl) if (self.payload_preview and pl) else ""
        with self.lock:
            self.buf.append(p)
        for fn in self.listeners:
            try:
                fn(p, pl)
            except Exception:
                pass
        return p

    # ---- queries
    def since(self, last_id, limit=400, host=None, proto=None, direction=None, search=None, iface=None):
        with self.lock:
            out = [p for p in self.buf if p["id"] > last_id]
        if host:
            out = [p for p in out if host in (p.get("src"), p.get("dst"), p.get("src_ip"), p.get("dst_ip"))]
        if proto:
            out = [p for p in out if p.get("proto", "").upper() == proto.upper()]
        if direction:
            out = [p for p in out if p.get("direction", "").upper() == direction.upper()]
        if iface:
            i_low = iface.lower()
            out = [p for p in out if i_low in str(p.get("iface", "")).lower()]
        if search:
            s_low = search.lower()
            out = [p for p in out if (
                s_low in str(p.get("src_ip", "")).lower() or
                s_low in str(p.get("dst_ip", "")).lower() or
                s_low in str(p.get("src", "")).lower() or
                s_low in str(p.get("dst", "")).lower() or
                s_low in str(p.get("info", "")).lower() or
                s_low in str(p.get("proto", "")).lower() or
                str(p.get("sport", "")) == s_low or
                str(p.get("dport", "")) == s_low
            )]
        return out[-limit:]

    def host_stats(self, label):
        sent = recv = bsent = brecv = 0
        peers = {}
        with self.lock:
            snap = list(self.buf)
        for p in snap:
            if p["src"] == label:
                sent += 1
                bsent += p["length"]
                peers[p["dst"]] = peers.get(p["dst"], 0) + 1
            elif p["dst"] == label:
                recv += 1
                brecv += p["length"]
                peers[p["src"]] = peers.get(p["src"], 0) + 1
        top = sorted(peers.items(), key=lambda x: -x[1])[:6]
        return {"label": label, "sent_pkts": sent, "recv_pkts": recv, "sent_bytes": bsent, "recv_bytes": brecv,
                "top_peers": [{"peer": k, "pkts": v} for k, v in top]}

    @staticmethod
    def to_row(p):
        """Convert a packet dict to the tshark-style row used by feature_extractor.extract_features()."""
        udp = p["proto"] in ("UDP", "DNS")
        return {"frame.time_epoch": p["ts"], "ip.src": p["src_ip"], "ip.dst": p["dst_ip"],
                "ip.proto": {"TCP": "6", "UDP": "17", "DNS": "17", "ICMP": "1"}.get(p["proto"], ""),
                "tcp.srcport": str(p["sport"]) if p["proto"] == "TCP" else "",
                "tcp.dstport": str(p["dport"]) if p["proto"] == "TCP" else "",
                "tcp.flags": f"0x{p.get('tcp_flags', 0):04x}" if p["proto"] == "TCP" else "",
                "frame.len": str(p["length"]), "udp.dstport": str(p["dport"]) if udp else "",
                "icmp.type": str(p["icmp_type"]) if p.get("icmp_type") is not None else "",
                "dns.flags.response": "" if p.get("dns_qr") is None else str(p["dns_qr"]),
                "dns.flags.rcode": "" if p.get("dns_rcode") is None or not p.get("dns_qr") else str(p["dns_rcode"]),
                "dns.qry.name": "", "http.response.code": str(p["http_code"]) if p.get("http_code") else "",
                "tcp.analysis.retransmission": "1" if p.get("retrans") else ""}
