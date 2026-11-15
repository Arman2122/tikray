# Only fixed synthetic probes are recorded. No packet payloads or arbitrary
# addresses from the router are written to the trace.
import pathlib
import select
import socket
import struct
import sys

mode, device, gateway_mac, router_mac, remote, marker, trace, wan, closed, peer, proxy_a, proxy_b, alternate, alternate_mac = sys.argv[1:]
trace = pathlib.Path(trace)
prefix = b"wd6b" + bytes.fromhex(marker)
target = socket.inet_aton(remote)
gateway_mac = bytes.fromhex(gateway_mac.replace(":", ""))
router_mac = bytes.fromhex(router_mac.replace(":", ""))
alternate = pathlib.Path(alternate)
alternate_mac = bytes.fromhex(alternate_mac.replace(":", ""))
servers = (proxy_a, proxy_b)


def client_probe(packet):
    if len(packet) == len(prefix) + 3 and packet[1:-2] == prefix and packet[:1] in (b"C", b"D"):
        port = int.from_bytes(packet[-2:], "big")
        if 33000 <= port <= 65000:
            return packet[:1], port
    return None, 0


def ip_class(address):
    if address == wan:
        return "wan"
    if address == closed:
        return "closed"
    if address == peer:
        return "peer"
    if address in servers:
        return "proxy"
    if address.startswith("172.30.252."):
        return "veth"
    return "other"


def mac_class(value):
    if value == router_mac:
        return "router"
    if value == gateway_mac:
        return "gateway"
    if value == alternate_mac and alternate.exists():
        return "gateway"
    return "other"


wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
wire.bind((device, 0))
if mode == "tap":
    # Capture forwarded frames on the actual CHR TAP before the Linux bridge
    # consumes them. ETH_P_IP on a slave may see only local protocol traffic.
    wire.setsockopt(263, 1, struct.pack("IHH8s", socket.if_nametoindex(device), 1, 0, b""))
socks = [wire]
udp = None
if mode == "gateway":
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((remote, 31947))
    socks.append(udp)
reported = 0
with trace.open("wb", buffering=0) as output:
    while True:
        ready, _, _ = select.select(socks, [], [])
        for sock in ready:
            if sock is udp:
                packet, address = udp.recvfrom(64)
                tag, _ = client_probe(packet)
                if tag == b"C" and address[0] in servers:
                    output.write(b"P")
                continue
            frame, metadata = wire.recvfrom(65535)
            if len(frame) < 43 or frame[12:14] != b"\x08\x00" or frame[23] != 17 or frame[30:34] != target:
                continue
            offset = 14 + 4 * (frame[14] & 15)
            if len(frame) < offset + 8:
                continue
            sport, dport, size, _ = struct.unpack_from("!4H", frame, offset)
            if dport != 31947:
                continue
            tag, original = client_probe(frame[offset + 8:offset + size])
            if tag is None:
                continue
            source = ip_class(socket.inet_ntoa(frame[26:30]))
            origin, dest = mac_class(frame[6:12]), mac_class(frame[:6])
            if tag == b"D" and source == "wan" and origin == "router" and dest == "gateway":
                output.write(b"Dg" if frame[:6] == gateway_mac else b"Da")
                continue
            output.write(b"C" if tag == b"C" else b"?")
            if reported < 8:
                # Public role, direction, assigned source port, TTL and MAC
                # classes certify provenance even if reverse-path filtering
                # prevents the UDP socket from receiving the leaking frame.
                with pathlib.Path(str(trace) + ".violations").open("a") as details:
                    details.write(f"{tag.decode()} {metadata[2]} {origin} {dest} {source} {sport} {original} {frame[22]}\n")
                reported += 1
