"""Packet parsing and normalization module.

Converts raw Scapy packet objects into structured records (dicts) containing:
- timestamp, source/destination IPs and ports
- protocol name (TCP, UDP, ICMP, ARP, IPv6, etc.)
- packet length in bytes
- truncated hex + ASCII payload preview

All parsing is read-only — packets are never modified or retransmitted.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw
except ImportError:
    # Fallback stubs so the module can be imported without Scapy installed
    ICMP = IP = TCP = UDP = IPv6 = ARP = Ether = Raw = None


# Map well-known IP protocol numbers to human-readable names
_PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}

# Regex patterns for 2-Factor Authentication (2FA / TOTP) manual secret keys,
# auth tokens, passwords, and sensitive credentials
_SENSITIVE_PATTERNS = [
    # 2FA / TOTP manual setup keys in URLs, parameters, headers, or JSON
    # e.g., secret=JBSWY3DPEHPK3PXP, totp=..., key=..., token=...
    re.compile(r'(?i)(secret|totp|otp|key|auth|password|token)\s*([:=])\s*([A-Za-z0-9+/=_~-]{6,64})'),
    # otpauth:// URI secret parameters
    re.compile(r'(?i)(otpauth://[^\s"\'<>]*[?&]secret=)([A-Za-z2-7]+)'),
    # Standalone Base32 2FA manual secret keys (16, 26, or 32 chars of [A-Z2-7] RFC 4648)
    # including space/hyphen delimited groups (e.g. "JBSW Y3DP EHPK 3PXP")
    re.compile(r'\b(?:[A-Z2-7]{4}[\s-]?){4,8}\b'),
    re.compile(r'\b[A-Z2-7]{16,32}\b'),
    # HTTP Authorization headers (Bearer / Basic)
    re.compile(r'(?i)(Authorization:\s*(?:Bearer|Basic)\s+)([A-Za-z0-9._~+/-]+=*)'),
]


def sanitize_payload(data: bytes) -> bytes:
    """Mask sensitive authentication credentials such as 2FA manual secret keys.

    Replaces sensitive 2FA manual setup codes, TOTP secrets, passwords, and tokens
    with asterisk bytes (0x2a '*'), ensuring credentials are redacted from both
    hexadecimal (displayed as '2a') and ASCII previews (displayed as '*').
    """
    if not data:
        return data

    text = data.decode("latin1", errors="replace")
    masked_text = text

    for rx in _SENSITIVE_PATTERNS:
        for match in rx.finditer(text):
            if match.lastindex and match.lastindex >= 2:
                start, end = match.span(match.lastindex)
            elif match.lastindex and match.lastindex == 1:
                start, end = match.span(1)
            else:
                start, end = match.span(0)
            masked_text = masked_text[:start] + ("*" * (end - start)) + masked_text[end:]

    return masked_text.encode("latin1", errors="replace")


def sanitize_text(text: str) -> str:
    """Mask 2FA manual secret keys and credentials in a plain string."""
    if not text:
        return text
    masked = text
    for rx in _SENSITIVE_PATTERNS:
        for match in rx.finditer(text):
            if match.lastindex and match.lastindex >= 2:
                start, end = match.span(match.lastindex)
            elif match.lastindex and match.lastindex == 1:
                start, end = match.span(1)
            else:
                start, end = match.span(0)
            masked = masked[:start] + ("*" * (end - start)) + masked[end:]
    return masked


def _safe_ascii(data: bytes) -> str:
    """Convert bytes to a safe ASCII string, replacing non-printable chars with '.'.

    Only printable ASCII characters (0x20–0x7E) are kept; everything else
    becomes a dot. This prevents terminal corruption and ensures the preview
    is always safe to display.
    """
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def _build_payload_preview(
    packet: Any,
    payload_bytes: int = 32,
    no_payload: bool = False,
    sanitize_credentials: bool = True,
) -> tuple[str, str]:
    """Extract a truncated hex + ASCII payload preview from a packet.

    Args:
        packet: Raw Scapy packet object.
        payload_bytes: Maximum number of payload bytes to include.
        no_payload: If True, skip payload extraction entirely (privacy mode).
        sanitize_credentials: If True, mask 2FA secret keys, passwords, and tokens.

    Returns:
        A tuple of (hex_string, ascii_string). Both empty if no payload
        is present or payload capture is disabled.
    """
    if no_payload or payload_bytes <= 0:
        return "", ""

    if Raw is None or not packet.haslayer(Raw):
        return "", ""

    full_payload = bytes(packet[Raw].load)
    if sanitize_credentials:
        full_payload = sanitize_payload(full_payload)

    raw_data = full_payload[:payload_bytes]
    hex_str = " ".join(f"{b:02x}" for b in raw_data)
    ascii_str = _safe_ascii(raw_data)

    # Indicate truncation if the full payload is longer than what we show
    if len(packet[Raw].load) > payload_bytes:
        hex_str += " ..."
        ascii_str += "..."

    return hex_str, ascii_str


def parse_packet(
    packet: Any,
    payload_bytes: int = 32,
    no_payload: bool = False,
    sanitize_credentials: bool = True,
) -> dict:
    """Parse a raw Scapy packet into a structured summary record.

    Extracts metadata passively from the packet's decoded layers without
    modifying or retransmitting it. Supports IPv4, IPv6, TCP, UDP, ICMP,
    ARP, and falls back to Ethernet or raw layer names for other protocols.

    Args:
        packet: Raw Scapy packet object.
        payload_bytes: Max payload bytes for the hex/ASCII preview.
        no_payload: If True, omit payload data entirely.

    Returns:
        A dict with keys: timestamp, src_ip, dst_ip, src_port, dst_port,
        protocol, length, payload_hex, payload_ascii.
    """
    # --- Timestamp ---
    timestamp = datetime.fromtimestamp(
        float(packet.time)
    ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Trim to milliseconds

    # --- Defaults ---
    src_ip = "-"
    dst_ip = "-"
    src_port = "-"
    dst_port = "-"
    protocol = packet.__class__.__name__

    # --- Network layer: extract IPs and base protocol ---
    if IP is not None and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # Store numeric protocol for transport-layer override below
        protocol = _PROTO_MAP.get(packet[IP].proto, str(packet[IP].proto))

    elif IPv6 is not None and packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        protocol = _PROTO_MAP.get(packet[IPv6].nh, f"IPv6/{packet[IPv6].nh}")

    elif ARP is not None and packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        protocol = "ARP"

    elif Ether is not None and packet.haslayer(Ether):
        # No IP layer — use MAC addresses as fallback identifiers
        src_ip = packet[Ether].src
        dst_ip = packet[Ether].dst
        protocol = f"Ether/0x{packet[Ether].type:04x}"

    # --- Transport layer: extract ports and override protocol name ---
    if TCP is not None and packet.haslayer(TCP):
        protocol = "TCP"
        src_port = str(packet[TCP].sport)
        dst_port = str(packet[TCP].dport)

    elif UDP is not None and packet.haslayer(UDP):
        protocol = "UDP"
        src_port = str(packet[UDP].sport)
        dst_port = str(packet[UDP].dport)

    elif ICMP is not None and packet.haslayer(ICMP):
        protocol = "ICMP"

    # --- Payload preview ---
    payload_hex, payload_ascii = _build_payload_preview(
        packet,
        payload_bytes=payload_bytes,
        no_payload=no_payload,
        sanitize_credentials=sanitize_credentials,
    )

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": len(packet),
        "payload_hex": payload_hex,
        "payload_ascii": payload_ascii,
    }
