"""Capture statistics tracking and display.

Provides the PacketStatistics class that tracks:
- Total packet count
- Protocol breakdown (how many TCP, UDP, ICMP, ARP, etc.)
- Top source IPs (top talkers sending traffic)
- Top destination IPs (most-targeted addresses)

Statistics are updated incrementally as packets arrive and rendered
as Rich tables at the end of a capture session.
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from .display import console, rprint


class PacketStatistics:
    """Tracks and renders capture session statistics.

    Usage:
        stats = PacketStatistics()
        stats.update(parsed_record)  # Call for each captured packet
        stats.render()               # Print final statistics
    """

    def __init__(self, top_n: int = 5) -> None:
        """Initialize statistics counters.

        Args:
            top_n: Number of top source/destination IPs to display.
        """
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.protocol_counts: Counter = Counter()
        self.source_ips: Counter = Counter()
        self.destination_ips: Counter = Counter()
        self._top_n = top_n

    def update(self, record: dict) -> None:
        """Update statistics with a new parsed packet record.

        Args:
            record: A dict as returned by parser.parse_packet().
        """
        self.total_packets += 1
        self.total_bytes += record.get("length", 0)
        self.protocol_counts[record["protocol"]] += 1

        src = record.get("src_ip", "-")
        dst = record.get("dst_ip", "-")
        if src and src != "-":
            self.source_ips[src] += 1
        if dst and dst != "-":
            self.destination_ips[dst] += 1

    def render(self) -> None:
        """Render all statistics tables to the terminal."""
        rprint("\n[bold cyan]=== Capture Statistics ===[/bold cyan]")
        rprint(f"  Total packets captured: [bold]{self.total_packets}[/bold]")
        rprint(f"  Total bytes captured:   [bold]{self.total_bytes:,}[/bold]")

        if self.total_packets == 0:
            rprint("[yellow]  No data to analyze.[/yellow]")
            return

        self._render_protocol_breakdown()
        self._render_top_talkers("Top Source IPs", self.source_ips)
        self._render_top_talkers("Top Destination IPs", self.destination_ips)

    def _render_protocol_breakdown(self) -> None:
        """Render protocol breakdown as a table with visual percentage bars."""
        rprint("")
        bar_len = 16
        if HAS_RICH and console:
            table = Table(title="Protocol Breakdown", title_style="bold")
            table.add_column("Protocol", style="cyan")
            table.add_column("Packets", justify="right")
            table.add_column("Percentage", justify="right")
            table.add_column("Distribution", style="green")

            for proto, count in self.protocol_counts.most_common():
                pct = (count / self.total_packets) * 100
                filled = int(round((pct / 100.0) * bar_len))
                bar_str = "[" + "#" * filled + "-" * (bar_len - filled) + "]"
                table.add_row(proto, str(count), f"{pct:.1f}%", bar_str)

            console.print(table)
        else:
            print("  Protocol Breakdown:")
            for proto, count in self.protocol_counts.most_common():
                pct = (count / self.total_packets) * 100
                filled = int(round((pct / 100.0) * bar_len))
                bar_str = "[" + "#" * filled + "-" * (bar_len - filled) + "]"
                print(f"    {proto:<8} {count:>5} ({pct:>5.1f}%)  {bar_str}")

    def _render_top_talkers(self, title: str, counter: Counter) -> None:
        """Render a top-N IP table."""
        if not counter:
            return

        rprint("")
        top_entries = counter.most_common(self._top_n)

        if HAS_RICH and console:
            table = Table(title=title, title_style="bold")
            table.add_column("IP Address")
            table.add_column("Packets", justify="right")
            table.add_column("Percentage", justify="right")

            total = sum(counter.values())
            for ip, count in top_entries:
                pct = (count / total) * 100
                table.add_row(ip, str(count), f"{pct:.1f}%")

            console.print(table)
        else:
            print(f"  {title}:")
            total = sum(counter.values())
            for ip, count in top_entries:
                pct = (count / total) * 100
                print(f"    {ip}: {count} ({pct:.1f}%)")
