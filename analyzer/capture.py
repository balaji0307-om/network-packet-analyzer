"""Network interface detection and live packet capture using Scapy.

This module provides:
- get_interfaces(): list available network interfaces
- get_interface_details(): list detailed metadata for interfaces (index, name, device, description, IP)
- get_default_interface(): auto-detect a sensible default interface
- validate_interface(): validate or resolve names/indexes (e.g. "Wi-Fi", 0, or device GUIDs)
- live_capture(): true streaming generator using Scapy's AsyncSniffer and a thread-safe Queue
- CaptureError: custom exception for permission and interface issues

All capture operations are strictly passive — no packets are injected,
modified, or retransmitted.
"""

from __future__ import annotations

import queue
import sys
from typing import Generator, Optional

try:
    from scapy.all import conf, get_if_addr, get_if_list
    from scapy.all import AsyncSniffer, Scapy_Exception
except ImportError:
    conf = None
    get_if_addr = None
    get_if_list = None
    AsyncSniffer = None
    Scapy_Exception = Exception


class CaptureError(Exception):
    """Raised when packet capture fails due to permission or interface issues.

    Common causes:
    - Insufficient privileges (not root/admin)
    - Invalid or unavailable network interface
    - Missing pcap library (libpcap/Npcap)
    - Scapy not installed
    """
    pass


def _require_scapy() -> None:
    """Verify that Scapy is importable; raise CaptureError if not."""
    if conf is None or get_if_list is None or AsyncSniffer is None:
        raise CaptureError(
            "Scapy is not installed. Install it with: pip install -r requirements.txt\n"
            "A raw-socket fallback is theoretically possible but OS-specific and far\n"
            "more limited than Scapy's protocol dissection and BPF filter support."
        )


def get_interfaces() -> list[str]:
    """Return a list of network interface names visible to Scapy."""
    _require_scapy()
    # Collect friendly names and device names
    seen = set()
    result = []
    
    # Check conf.ifaces for friendly and device names
    ifaces_dict = getattr(conf, "ifaces", {})
    if ifaces_dict:
        for dev, iface_obj in ifaces_dict.items():
            name = getattr(iface_obj, "name", None)
            if name and name not in seen:
                seen.add(name)
                result.append(name)
            dev_str = str(dev)
            if dev_str not in seen:
                seen.add(dev_str)
                result.append(dev_str)

    # Fallback to get_if_list() if empty
    if not result:
        for dev in get_if_list():
            if dev not in seen:
                seen.add(dev)
                result.append(dev)

    return result


def get_interface_details() -> list[dict]:
    """Return structured details for each available interface."""
    _require_scapy()
    details = []
    ifaces_dict = getattr(conf, "ifaces", {})

    if ifaces_dict:
        for idx, (dev, iface_obj) in enumerate(ifaces_dict.items()):
            friendly_name = getattr(iface_obj, "name", str(dev))
            description = getattr(iface_obj, "description", "")
            ip_addr = getattr(iface_obj, "ip", None) or "-"
            details.append({
                "index": idx,
                "name": friendly_name,
                "device": str(dev),
                "description": description,
                "ip": ip_addr,
            })
    else:
        for idx, dev in enumerate(get_if_list()):
            ip_addr = "-"
            try:
                if get_if_addr:
                    ip_addr = get_if_addr(dev) or "-"
            except Exception:
                pass
            details.append({
                "index": idx,
                "name": dev,
                "device": dev,
                "description": "",
                "ip": ip_addr,
            })

    return details


def get_default_interface() -> str:
    """Auto-detect a sensible default network interface.

    Strategy:
    1. Use Scapy's configured default interface (conf.iface) if available.
    2. Fall back to the first interface with a non-zero IP address.
    3. As a last resort, return the first interface in the list.

    Raises:
        CaptureError: If no interfaces are found at all.
    """
    _require_scapy()

    # Strategy 1: Scapy's default
    default_iface = getattr(conf, "iface", None)
    if default_iface:
        # Prefer the network device identifier or name
        return str(default_iface)

    # Strategy 2: first interface with an assigned IP
    for detail in get_interface_details():
        if detail["ip"] not in ("0.0.0.0", "-", "", None):
            return detail["device"]

    # Strategy 3: first available interface
    ifaces = get_interfaces()
    if not ifaces:
        raise CaptureError(
            "No network interfaces found. Ensure your system has active\n"
            "network adapters and that Npcap (Windows) or libpcap (Linux/macOS)\n"
            "is installed."
        )
    return ifaces[0]


def validate_interface(interface: Optional[str]) -> str:
    """Validate and resolve a user-supplied interface name, index, or device.

    Supports:
    - Index number (e.g. "0", "1")
    - Friendly name (e.g. "Wi-Fi", "eth0") case-insensitively
    - Raw device string (e.g. "\\Device\\NPF_{...}")
    - None (auto-detects default)

    Returns:
        A resolved, valid interface identifier for Scapy.

    Raises:
        CaptureError: If the specified interface cannot be resolved.
    """
    _require_scapy()

    if not interface:
        return get_default_interface()

    interface_str = str(interface).strip()
    details = get_interface_details()

    # 1. Check if user passed an index number (e.g. "0", "1")
    if interface_str.isdigit():
        idx = int(interface_str)
        if 0 <= idx < len(details):
            return details[idx]["device"]

    # 2. Match against friendly name or device string (exact or case-insensitive)
    for item in details:
        if interface_str.lower() in (item["name"].lower(), item["device"].lower()):
            return item["device"]

    # 3. Check Scapy dev_from_name if available
    try:
        ifaces = getattr(conf, "ifaces", None)
        if ifaces and hasattr(ifaces, "dev_from_name"):
            dev = ifaces.dev_from_name(interface_str)
            if dev:
                return getattr(dev, "network_name", str(dev))
    except Exception:
        pass

    # 4. Fallback check in get_interfaces()
    available = get_interfaces()
    if interface_str in available:
        return interface_str

    # Build clean formatted list for the error message
    listing = "\n".join(
        f"  [{d['index']}] {d['name']} ({d['device']})"
        for d in details
    )
    raise CaptureError(
        f"Interface '{interface}' not found.\n"
        f"Available interfaces:\n{listing}"
    )


def _map_exception(exc: Exception, interface: str) -> CaptureError:
    """Translate underlying OS / pcap / Scapy exceptions into a user-friendly CaptureError."""
    err_str = str(exc)
    if isinstance(exc, PermissionError) or "permission" in err_str.lower() or "access is denied" in err_str.lower():
        platform_hint = (
            "Run your terminal as Administrator."
            if sys.platform == "win32"
            else "Use sudo to run with elevated privileges."
        )
        return CaptureError(
            f"Permission denied: packet capture requires elevated privileges.\n"
            f"{platform_hint}\nOriginal error: {exc}"
        )

    if "not found" in err_str.lower() or "syntax" in err_str.lower():
        return CaptureError(f"Capture setup failed: {exc}")

    return CaptureError(
        f"Could not capture on interface '{interface}'.\n"
        f"Ensure the interface exists, BPF filter syntax is valid, and Npcap/libpcap is installed.\n"
        f"Original error: {exc}"
    )


def live_capture(
    interface: str,
    bpf_filter: Optional[str] = None,
    count: int = 0,
) -> Generator:
    """True streaming generator that yields raw Scapy packets from a live capture.

    Architecture:
        packet arrives -> Scapy prn callback -> thread-safe Queue -> generator yield

    Packets are streamed one-by-one with store=False, ensuring low memory
    overhead and true real-time processing.

    Args:
        interface: Network interface name or device to capture on.
        bpf_filter: Optional BPF filter string (e.g. "tcp", "udp port 53").
        count: Number of packets to capture. 0 means capture until interrupted.

    Yields:
        Raw Scapy packet objects in real-time as they arrive.

    Raises:
        CaptureError: On permission errors, invalid filters, or capture failures.
    """
    _require_scapy()

    pkt_queue: queue.Queue = queue.Queue()
    target = count if count > 0 else 0
    packets_yielded = 0

    # Initialize AsyncSniffer with store=False for zero buffering in Scapy
    try:
        sniffer = AsyncSniffer(
            iface=interface,
            filter=bpf_filter if bpf_filter else None,
            prn=pkt_queue.put,
            store=False,
        )
        sniffer.start()
    except Exception as exc:
        raise _map_exception(exc, interface) from exc

    try:
        while True:
            try:
                # Poll queue with short timeout to stay responsive to interrupts and errors
                pkt = pkt_queue.get(timeout=0.2)
                yield pkt
                packets_yielded += 1

                if target > 0 and packets_yielded >= target:
                    break

            except queue.Empty:
                # Check if background sniffer encountered a fatal error
                thread_exc = getattr(sniffer, "exception", None)
                if thread_exc:
                    raise _map_exception(thread_exc, interface)

                if sniffer.thread and not sniffer.thread.is_alive():
                    if thread_exc:
                        raise _map_exception(thread_exc, interface)
                    break

    except Exception as exc:
        if isinstance(exc, CaptureError):
            raise
        raise _map_exception(exc, interface) from exc

    finally:
        # Gracefully stop the background sniffer
        if getattr(sniffer, "running", False):
            try:
                sniffer.stop()
            except Exception:
                pass
