#!/usr/bin/env python3
"""
pcap_exporter.py - Standard Libpcap 2.4 File Exporter for NetGuard.

Exports captured and live packets into standard .pcap binary format
compatible with Wireshark desktop, tcpdump, TShark, and Scapy.
"""
import struct
import socket
import time

PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def ip_checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def parse_flags_to_int(flags_str):
    flg = 0
    if not flags_str:
        return 0x10  # default ACK
    f = str(flags_str).upper()
    if "FIN" in f: flg |= 0x01
    if "SYN" in f: flg |= 0x02
    if "RST" in f: flg |= 0x04
    if "PSH" in f: flg |= 0x08
    if "ACK" in f: flg |= 0x10
    if "URG" in f: flg |= 0x20
    return flg or 0x10

def sanitize_ip(ip_str, fallback="10.0.0.1"):
    try:
        if not ip_str or ":" in str(ip_str):
            # If IPv6 or empty, fallback or hash to a distinct 10.x.x.x IPv4 for PCAP frame
            return fallback
        socket.inet_aton(str(ip_str))
        return str(ip_str)
    except Exception:
        return fallback

def packet_to_eth_frame(p):
    """Converts a NetGuard packet dictionary into a full binary Ethernet II + IPv4 + TCP/UDP frame."""
    if p.get("raw_bytes") and isinstance(p["raw_bytes"], (bytes, bytearray)):
        return bytes(p["raw_bytes"])

    src_ip = sanitize_ip(p.get("src_ip"), fallback="10.0.1.11")
    dst_ip = sanitize_ip(p.get("dst_ip"), fallback="142.251.221.110")
    sport = int(p.get("sport") or 80)
    dport = int(p.get("dport") or 80)
    proto = str(p.get("proto") or "TCP").upper()
    flags_str = str(p.get("flags") or "ACK")
    seq = int(p.get("seq") or 100000)
    ack = int(p.get("ack") or 50000)
    win = int(p.get("window") or 64240)

    # Determine payload
    payload = b""
    if p.get("payload_preview"):
        payload = p["payload_preview"].encode("utf-8", "replace")
    elif p.get("info"):
        payload = p["info"].encode("utf-8", "replace")
    else:
        payload = b"NetGuard Captured Traffic Payload"

    # Limit payload to max snapshot size
    payload = payload[:1400]

    # Ethernet Header (14 bytes)
    eth_hdr = b"\x00\x15\x5d\x8a\x3f\x12\x00\x15\x5d\x8a\x3f\x11\x08\x00"

    # Protocol number: 6 = TCP, 17 = UDP, 1 = ICMP
    if proto in ("TCP", "TLS", "HTTP"):
        proto_num = 6
        flg_val = parse_flags_to_int(flags_str)
        trans_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flg_val, win, 0, 0)
    elif proto in ("UDP", "DNS", "QUIC"):
        proto_num = 17
        trans_hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    elif proto == "ICMP":
        proto_num = 1
        trans_hdr = struct.pack("!BBHHH", 8 if "request" in str(p.get("info", "")).lower() else 0, 0, 0, 0x1234, 1)
        csum = ip_checksum(trans_hdr + payload)
        trans_hdr = trans_hdr[:2] + struct.pack("!H", csum) + trans_hdr[4:]
    else:
        proto_num = 6
        trans_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (5 << 4), 0x10, win, 0, 0)

    # IPv4 Header (20 bytes)
    total_len = 20 + len(trans_hdr) + len(payload)
    ip_id = int(p.get("ip_id") or 0x4321)
    ip_hdr_raw = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ip_id, 0x4000, 64, proto_num, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    )
    ip_csum = ip_checksum(ip_hdr_raw)
    ip_hdr = ip_hdr_raw[:10] + struct.pack("!H", ip_csum) + ip_hdr_raw[12:]

    return eth_hdr + ip_hdr + trans_hdr + payload

def packets_to_pcap(packet_list):
    """Converts a list of NetGuard packet dictionaries into a binary PCAP buffer."""
    buf = bytearray(PCAP_GLOBAL_HEADER)
    for p in packet_list:
        frame = packet_to_eth_frame(p)
        ts = float(p.get("ts") or time.time())
        sec = int(ts)
        usec = int((ts % 1) * 1000000)
        pkt_hdr = struct.pack("<IIII", sec, usec, len(frame), len(frame))
        buf.extend(pkt_hdr)
        buf.extend(frame)
    return bytes(buf)
