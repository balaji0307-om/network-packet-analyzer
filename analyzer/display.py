"""Rich terminal display for captured packets.

Provides the PacketTable class that accumulates parsed packet records and
renders them as a formatted Rich table in the terminal. Includes a
fallback plain-text renderer if Rich is unavailable.
"""

from __future__ import annotations

from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


import sys

# Ensure UTF-8 console output on Windows to prevent UnicodeEncodeError
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

# Shared console instance — used throughout the application for consistent output
console = Console(width=160) if HAS_RICH else None


def _print_fallback(message: str) -> None:
    """Print to stdout, stripping Rich markup if Rich is unavailable."""
    import re
    cleaned = re.sub(r"\[/?[a-z ]+\]", "", message)
    print(cleaned)


def rprint(message: str) -> None:
    """Print a message using Rich console if available, else plain print."""
    if console:
        console.print(message)
    else:
        _print_fallback(message)


class PacketTable:
    """Accumulates packet records and renders them as a Rich terminal table.

    Usage:
        table = PacketTable()
        table.add_packet(parsed_record)  # Add records as they arrive
        table.render()                   # Print the final table
    """

    # Column definitions: (header, justify, style, no_wrap)
    _COLUMNS = [
        ("#", "right", "bold", True),
        ("Timestamp", "left", None, True),
        ("Source", "left", None, True),
        ("Destination", "left", None, True),
        ("Protocol", "center", "cyan", True),
        ("Length", "right", None, True),
        ("Payload Preview", "left", None, False),
    ]

    def __init__(self) -> None:
        self._records: list[dict] = []

    @property
    def count(self) -> int:
        """Number of packets currently in the table."""
        return len(self._records)

    def add_packet(self, record: dict) -> None:
        """Add a parsed packet record to the table.

        Args:
            record: A dict as returned by parser.parse_packet().
        """
        self._records.append(record)

    def _format_endpoint(self, ip: str, port: str) -> str:
        """Format an IP:port pair, omitting the port if it's '-'."""
        if port and port != "-":
            return f"{ip}:{port}"
        return ip

    def _format_payload(self, record: dict) -> str:
        """Format the payload hex + ASCII preview for display."""
        hex_part = record.get("payload_hex", "")
        ascii_part = record.get("payload_ascii", "")
        if not hex_part and not ascii_part:
            return ""
        return f"{hex_part}  |  {ascii_part}"

    def render(self) -> None:
        """Render the packet table to the terminal.

        Prints a Rich table if Rich is available, otherwise falls back
        to plain-text output. Shows a message if no packets were captured.
        """
        if not self._records:
            rprint("[yellow]No packets captured.[/yellow]")
            return

        if HAS_RICH:
            self._render_rich()
        else:
            self._render_plain()

    def _render_rich(self) -> None:
        """Render using Rich tables with color and formatting."""
        table = Table(
            title="Captured Packets",
            show_lines=False,
            expand=True,
            title_style="bold cyan",
        )

        for header, justify, style, no_wrap in self._COLUMNS:
            table.add_column(header, justify=justify, style=style, no_wrap=no_wrap)

        for idx, record in enumerate(self._records, start=1):
            source = self._format_endpoint(record["src_ip"], record["src_port"])
            dest = self._format_endpoint(record["dst_ip"], record["dst_port"])
            payload = self._format_payload(record)

            table.add_row(
                str(idx),
                record["timestamp"],
                source,
                dest,
                record["protocol"],
                str(record["length"]),
                payload,
            )

        console.print(table)

    def _render_plain(self) -> None:
        """Fallback plain-text table renderer."""
        headers = [h for h, *_ in self._COLUMNS]
        rows: list[list[str]] = []

        for idx, record in enumerate(self._records, start=1):
            source = self._format_endpoint(record["src_ip"], record["src_port"])
            dest = self._format_endpoint(record["dst_ip"], record["dst_port"])
            payload = self._format_payload(record)
            rows.append([str(idx), record["timestamp"], source, dest,
                         record["protocol"], str(record["length"]), payload])

        # Calculate column widths
        widths = [
            max(len(headers[i]), *(len(row[i]) for row in rows))
            for i in range(len(headers))
        ]
        divider = "-+-".join("-" * w for w in widths)
        header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))

        print(f"\n  Captured Packets")
        print(header_line)
        print(divider)
        for row in rows:
            print(" | ".join(v.ljust(w) for v, w in zip(row, widths)))
        print()
