from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PacketSummary:
    """Safe, display/export-friendly summary of a captured packet."""

    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: str
    destination_port: str
    protocol: str
    length: int
    payload_hex: str
    payload_ascii: str

    def payload_preview(self) -> str:
        if not self.payload_hex and not self.payload_ascii:
            return ""
        return f"{self.payload_hex} | {self.payload_ascii}"
