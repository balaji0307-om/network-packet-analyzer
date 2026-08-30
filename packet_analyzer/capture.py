from __future__ import annotations

from typing import Callable

try:
    from scapy.all import Scapy_Exception, sniff
except ImportError:  # pragma: no cover - handled by interfaces.require_scapy
    Scapy_Exception = Exception
    sniff = None

from .interfaces import require_scapy
from .models import PacketSummary
from .parser import parse_packet


PacketCallback = Callable[[PacketSummary], None]


def build_bpf_filter(protocol: str | None = None, port: int | None = None, bpf: str | None = None) -> str:
    if bpf:
        return bpf.strip()

    parts: list[str] = []
    if protocol:
        parts.append(protocol.lower())
    if port is not None:
        parts.append(f"port {port}")

    return " and ".join(parts)


def capture_packets(
    interface: str,
    count: int | None,
    bpf_filter: str,
    on_packet: PacketCallback | None = None,
) -> list[PacketSummary]:
    """Capture packets passively and return parsed summaries."""

    require_scapy()
    captured: list[PacketSummary] = []

    def handle_packet(packet: object) -> None:
        summary = parse_packet(packet)
        captured.append(summary)
        if on_packet:
            on_packet(summary)

    try:
        sniff(
            iface=interface,
            filter=bpf_filter or None,
            prn=handle_packet,
            store=False,
            count=count or 0,
        )
    except PermissionError as exc:
        raise PermissionError(
            "Packet capture requires administrator/root privileges. "
            "Run the terminal as Administrator on Windows or use sudo on Linux/macOS."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Could not start packet capture on interface '{interface}'. "
            "Check the interface name and ensure Npcap/libpcap is installed."
        ) from exc
    except Scapy_Exception as exc:
        raise RuntimeError(f"Scapy capture failed: {exc}") from exc

    return captured
