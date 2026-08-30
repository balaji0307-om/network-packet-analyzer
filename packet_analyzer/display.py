from __future__ import annotations

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:  # pragma: no cover - used only before dependencies are installed
    Console = None
    Table = None

from .models import PacketSummary


class PlainConsole:
    def print(self, message: object = "") -> None:
        text = str(message)
        for markup in ("[bold cyan]", "[/bold cyan]", "[green]", "[/green]", "[yellow]", "[/yellow]", "[bold red]", "[/bold red]", "[bold]", "[/bold]"):
            text = text.replace(markup, "")
        print(text)


console = Console(width=140) if Console else PlainConsole()


def print_banner(interface: str, bpf_filter: str, count: int | None) -> None:
    target = str(count) if count else "until interrupted"
    console.print(f"[bold cyan]Passive Network Packet Analyzer[/bold cyan]")
    console.print(f"Interface: [green]{interface}[/green]")
    console.print(f"BPF filter: [yellow]{bpf_filter or 'none'}[/yellow]")
    console.print(f"Capture target: [yellow]{target}[/yellow]\n")


def _plain_packet_table(rows: list[PacketSummary]) -> str:
    headers = ["#", "Timestamp", "Source", "Destination", "Protocol", "Length", "Payload Preview"]
    rendered_rows: list[list[str]] = []
    for index, summary in enumerate(rows, start=1):
        source = f"{summary.source_ip}:{summary.source_port}" if summary.source_port != "-" else summary.source_ip
        destination = (
            f"{summary.destination_ip}:{summary.destination_port}"
            if summary.destination_port != "-"
            else summary.destination_ip
        )
        rendered_rows.append(
            [
                str(index),
                summary.timestamp,
                source,
                destination,
                summary.protocol,
                str(summary.length),
                summary.payload_preview(),
            ]
        )

    widths = [
        max(len(row[column]) for row in [headers, *rendered_rows])
        for column in range(len(headers))
    ]
    divider = "-+-".join("-" * width for width in widths)
    lines = [" | ".join(value.ljust(widths[index]) for index, value in enumerate(headers)), divider]
    lines.extend(" | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rendered_rows)
    return "\n".join(lines)


def build_packet_table(rows: list[PacketSummary]):
    if Table is None:
        return _plain_packet_table(rows)

    table = Table(title="Captured Packet Summaries", show_lines=False, expand=True)
    table.add_column("#", justify="right", style="bold")
    table.add_column("Timestamp", no_wrap=True)
    table.add_column("Source", no_wrap=True)
    table.add_column("Destination", no_wrap=True)
    table.add_column("Protocol", style="cyan", no_wrap=True)
    table.add_column("Length", justify="right", no_wrap=True)
    table.add_column("Payload Preview", overflow="ellipsis")

    for index, summary in enumerate(rows, start=1):
        source = f"{summary.source_ip}:{summary.source_port}" if summary.source_port != "-" else summary.source_ip
        destination = (
            f"{summary.destination_ip}:{summary.destination_port}"
            if summary.destination_port != "-"
            else summary.destination_ip
        )
        table.add_row(
            str(index),
            summary.timestamp,
            source,
            destination,
            summary.protocol,
            str(summary.length),
            summary.payload_preview(),
        )

    return table


def print_packet_table(rows: list[PacketSummary]) -> None:
    if rows:
        console.print(build_packet_table(rows))
    else:
        console.print("[yellow]No packets captured.[/yellow]")


def print_error(message: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {message}")
