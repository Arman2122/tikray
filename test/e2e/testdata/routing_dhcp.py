"""Obtain a real RouterOS DHCP ACK without changing the lab namespace routes."""

import secrets
import socket
import struct
import sys
import time
from pathlib import Path

interface = "eth0"
mac = bytes.fromhex(Path("/sys/class/net/eth0/address").read_text().strip().replace(":", ""))
requested = socket.inet_aton(sys.argv[1])
xid = secrets.token_bytes(4)
broadcast = b"\xff" * 4
dhcp_cookie = bytes.fromhex("63825363")


def frame(kind, server):
    # The two test clients already have static addresses. DHCP must go on the
    # wire from 0.0.0.0, as a client still in INIT would send it.
    bootp = struct.pack("!BBBB4sHH16x6s10x64x128x", 1, 1, 6, 0, xid, 0, 0x8000, mac)
    options = bytes((53, 1, kind, 50, 4)) + requested
    if server:
        options += bytes((54, 4)) + server
    payload = (bootp + dhcp_cookie + options + b"\xff").ljust(300, b"\0")
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes(4), broadcast)
    total = sum(struct.unpack("!10H", ip))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    ip = ip[:10] + struct.pack("!H", ~total & 0xffff) + ip[12:]
    return b"\xff" * 6 + mac + b"\x08\x00" + ip + udp


def reply_server(raw, expected):
    if len(raw) < 282 or raw[23] != 17:
        return None
    udp = 14 + 4 * (raw[14] & 15)
    if raw[udp:udp + 4] != struct.pack("!HH", 67, 68):
        return None
    msg = raw[udp + 8:]
    if (msg[:1] != b"\x02" or msg[4:8] != xid or msg[16:20] != requested
            or msg[28:34] != mac or msg[236:240] != dhcp_cookie):
        return None
    i = 240
    options = {}
    while i < len(msg):
        tag = msg[i]
        i += 1
        if tag == 255:
            break
        if tag == 0:
            continue
        if i >= len(msg) or i + 1 + msg[i] > len(msg):
            return None
        length = msg[i]
        options[tag] = msg[i + 1:i + 1 + length]
        i += length + 1
    if options.get(53) == bytes((expected,)) and len(options.get(54, b"")) == 4:
        return options[54]
    return None


def exchange(sock, kind, expected, server=b""):
    request = frame(kind, server)
    for _ in range(15):
        sock.send(request)
        deadline = time.monotonic() + 1
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                candidate = reply_server(sock.recv(2000), expected)
            except socket.timeout:
                break
            if candidate and (not server or candidate == server):
                return candidate
    raise SystemExit(expected)


with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sock:
    sock.bind((interface, 0))
    offering_server = exchange(sock, 1, 2)
    exchange(sock, 3, 5, offering_server)
