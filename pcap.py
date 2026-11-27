"""Put a lab transcript into synthetic TCP/IP frames for offline viewing."""
import ipaddress
import struct
from pathlib import Path

CLIENT = ipaddress.IPv4Address("192.0.2.10").packed
SERVER = ipaddress.IPv4Address("192.0.2.20").packed
SYN, ACK, PSH, FIN = 2, 16, 8, 1


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(word for (word,) in struct.iter_unpack("!H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def write_trace(path: Path, server_port: int, transcript):
    """Record generated frames. No packet sniffing, socket, or injection."""
    ports = (49152, server_port)
    addresses = (CLIENT, SERVER)
    sequence = [1000, 9000]
    packets = []

    def add(side, flags, payload=b""):
        peer = 1 - side
        src, dst = addresses[side], addresses[peer]
        acknowledgment = sequence[peer] if flags & ACK else 0
        tcp = struct.pack(
            "!HHIIBBHHH", ports[side], ports[peer], sequence[side],
            acknowledgment, 0x50, flags, 65535, 0, 0
        )
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), len(packets),
            0x4000, 64, 6, 0, src, dst
        )
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        packets.append(ip + tcp + payload)
        sequence[side] += len(payload) + bool(flags & SYN) + bool(flags & FIN)

    add(0, SYN)
    add(1, SYN | ACK)
    add(0, ACK)
    for side, chunk in transcript:
        for offset in range(0, len(chunk), 1200):
            add(side, PSH | ACK, chunk[offset:offset + 1200])
            add(1 - side, ACK)
    add(0, FIN | ACK)
    add(1, FIN | ACK)
    add(0, ACK)
    with path.open("wb") as out:
        # Classic PCAP, LINKTYPE_RAW (IPv4 packets with no Ethernet header).
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for step, packet in enumerate(packets):
            out.write(struct.pack("<IIII", 1700000000, step * 1000, len(packet), len(packet)))
            out.write(packet)
