from __future__ import annotations

from collections import Counter

from .display import Table, console
from .models import PacketSummary


def protocol_breakdown(rows: list[PacketSummary]) -> Counter[str]:
    return Counter(row.protocol for row in rows)


def top_talkers(rows: list[PacketSummary], limit: int = 5) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for row in rows:
        if row.source_ip != "-":
            counts[row.source_ip] += 1
        if row.destination_ip != "-":
            counts[row.destination_ip] += 1
    return counts.most_common(limit)


def print_statistics(rows: list[PacketSummary]) -> None:
    console.print("\n[bold cyan]Capture Statistics[/bold cyan]")
    console.print(f"Total packets: [bold]{len(rows)}[/bold]")

    if Table is None:
        console.print("\nProtocol Breakdown")
        for protocol, count in protocol_breakdown(rows).most_common():
            console.print(f"{protocol}: {count}")

        console.print("\nTop Talkers by IP")
        for ip_address, count in top_talkers(rows):
            console.print(f"{ip_address}: {count}")
        return

    protocol_table = Table(title="Protocol Breakdown")
    protocol_table.add_column("Protocol")
    protocol_table.add_column("Packets", justify="right")
    for protocol, count in protocol_breakdown(rows).most_common():
        protocol_table.add_row(protocol, str(count))
    console.print(protocol_table)

    talkers_table = Table(title="Top Talkers by IP")
    talkers_table.add_column("IP / Host")
    talkers_table.add_column("Appearances", justify="right")
    for ip_address, count in top_talkers(rows):
        talkers_table.add_row(ip_address, str(count))
    console.print(talkers_table)
