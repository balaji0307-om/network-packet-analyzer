from __future__ import annotations

from typing import Optional

try:
    from scapy.all import conf, get_if_addr, get_if_list
except ImportError:  # pragma: no cover - handled at runtime for clearer CLI errors
    conf = None
    get_if_addr = None
    get_if_list = None


def require_scapy() -> None:
    if conf is None or get_if_list is None:
        raise RuntimeError(
            "Scapy is not installed. Install it with 'pip install -r requirements.txt'. "
            "A raw-socket fallback is possible in theory, but it is OS-specific and much "
            "more limited than Scapy's passive packet capture and protocol parsing."
        )


def list_interfaces() -> list[str]:
    require_scapy()
    return list(get_if_list())


def auto_detect_interface() -> str:
    """Pick Scapy's default interface, falling back to the first interface with an IP."""

    require_scapy()
    default_iface = getattr(conf, "iface", None)
    if default_iface:
        return str(default_iface)

    for iface in list_interfaces():
        try:
            if get_if_addr and get_if_addr(iface) != "0.0.0.0":
                return iface
        except Exception:
            continue

    interfaces = list_interfaces()
    if not interfaces:
        raise RuntimeError("No network interfaces were found.")
    return interfaces[0]


def validate_interface(interface: Optional[str]) -> str:
    """Validate a requested interface or select a reasonable default."""

    if not interface:
        return auto_detect_interface()

    interfaces = list_interfaces()
    if interface not in interfaces:
        available = ", ".join(interfaces) if interfaces else "none"
        raise ValueError(f"Invalid interface '{interface}'. Available interfaces: {available}")
    return interface
