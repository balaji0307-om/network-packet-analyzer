from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from .models import PacketSummary
from .parser import parse_packet


def demo_packets() -> list[PacketSummary]:
    """Build local sample packets for demonstrations without live capture access."""

    ethernet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    packets = [
        ethernet / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=51514, dport=443) / Raw(b"TLS application data preview"),
        ethernet / IP(src="192.168.1.22", dst="8.8.8.8") / UDP(sport=53122, dport=53) / Raw(b"\x12\x34 DNS query preview"),
        ethernet / IP(src="192.168.1.1", dst="192.168.1.10") / ICMP() / Raw(b"ping reply preview"),
        ethernet / ARP(psrc="192.168.1.30", pdst="192.168.1.1"),
    ]
    return [parse_packet(packet) for packet in packets]
