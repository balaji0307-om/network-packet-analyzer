from __future__ import annotations

from datetime import datetime
from typing import Any

try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw
except ImportError:  # pragma: no cover - imports are validated by interfaces.require_scapy
    ICMP = IP = TCP = UDP = IPv6 = ARP = Ether = Raw = None

from .models import PacketSummary


MAX_PAYLOAD_BYTES = 16


def _safe_ascii(data: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data)


def _payload_preview(packet: Any, max_bytes: int = MAX_PAYLOAD_BYTES) -> tuple[str, str]:
    if Raw is None or not packet.haslayer(Raw):
        return "", ""

    payload = bytes(packet[Raw].load[:max_bytes])
    hex_preview = " ".join(f"{byte:02x}" for byte in payload)
    ascii_preview = _safe_ascii(payload)

    if len(packet[Raw].load) > max_bytes:
        hex_preview += " ..."
        ascii_preview += "..."

    return hex_preview, ascii_preview


def parse_packet(packet: Any) -> PacketSummary:
    """Extract passive metadata without modifying, transmitting, or responding to packets."""

    timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    source_ip = "-"
    destination_ip = "-"
    source_port = "-"
    destination_port = "-"
    protocol = packet.__class__.__name__

    # Layer checks move from specific network protocols to transport protocols.
    # Scapy's haslayer/getitem API safely exposes decoded fields only when present.
    if IP is not None and packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto
    elif IPv6 is not None and packet.haslayer(IPv6):
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst
        protocol = packet[IPv6].nh
    elif ARP is not None and packet.haslayer(ARP):
        source_ip = packet[ARP].psrc
        destination_ip = packet[ARP].pdst
        protocol = "ARP"
    elif Ether is not None and packet.haslayer(Ether):
        source_ip = packet[Ether].src
        destination_ip = packet[Ether].dst

    if TCP is not None and packet.haslayer(TCP):
        protocol = "TCP"
        source_port = str(packet[TCP].sport)
        destination_port = str(packet[TCP].dport)
    elif UDP is not None and packet.haslayer(UDP):
        protocol = "UDP"
        source_port = str(packet[UDP].sport)
        destination_port = str(packet[UDP].dport)
    elif ICMP is not None and packet.haslayer(ICMP):
        protocol = "ICMP"
    elif protocol == 1:
        protocol = "ICMP"
    elif protocol == 6:
        protocol = "TCP"
    elif protocol == 17:
        protocol = "UDP"
    else:
        protocol = str(protocol)

    payload_hex, payload_ascii = _payload_preview(packet)

    return PacketSummary(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        length=len(packet),
        payload_hex=payload_hex,
        payload_ascii=payload_ascii,
    )
