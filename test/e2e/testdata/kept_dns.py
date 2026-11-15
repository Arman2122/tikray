import socket
import struct
import sys
import time


def skip_name(packet, offset):
    while offset < len(packet):
        span = packet[offset]
        if span == 0:
            return offset + 1
        if span & 0xC0 == 0xC0:
            return offset + 2
        if span > 63:
            raise ValueError()
        offset += 1 + span
    raise ValueError()


def answer(packet, ident):
    tx, flags, questions, answers, _, _ = struct.unpack_from("!6H", packet)
    if tx != ident or flags & 0x800F != 0x8000 or questions != 1:
        return None
    at = skip_name(packet, 12) + 4
    for _ in range(answers):
        at = skip_name(packet, at)
        typ, cls, _, size = struct.unpack_from("!HHIH", packet, at)
        at += 10
        if typ == 1 and cls == 1 and size == 4:
            return socket.inet_ntoa(packet[at:at + size])
        at += size
    return None


client, filepath = sys.argv[1:]
endpoint = ("203.0.113.53", 53)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((client, 32245))
sock.settimeout(.4)
with open(filepath, "wb", buffering=0) as output:
    while True:
        counter = time.monotonic_ns()
        ident = counter & 0xFFFF
        labels = (str(counter) + ".kept-open.foreign.routing-probe.test").split(".")
        name = b"".join(bytes([len(x)]) + x.encode() for x in labels) + b"\0"
        query = struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0) + name + struct.pack("!2H", 1, 1)
        sock.sendto(query, endpoint)
        try:
            data, sender = sock.recvfrom(4096)
            addr = answer(data, ident) if sender == endpoint else None
            if addr == "198.18.53.2":
                output.write(b"P")
            elif addr == "198.18.54.1":
                output.write(b"D")
        except (socket.timeout, OSError, ValueError, struct.error):
            pass
        time.sleep(.12)
