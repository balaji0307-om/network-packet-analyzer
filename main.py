from __future__ import annotations

import argparse
import sys

from packet_analyzer.capture import build_bpf_filter, capture_packets
from packet_analyzer.demo import demo_packets
from packet_analyzer.display import console, print_banner, print_error, print_packet_table
from packet_analyzer.export import export_summaries
from packet_analyzer.interfaces import list_interfaces, validate_interface
from packet_analyzer.models import PacketSummary
from packet_analyzer.stats import print_statistics


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def port_number(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Passive Python network packet analyzer using Scapy.",
    )
    parser.add_argument("-i", "--interface", help="Network interface to capture from")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces and exit")
    parser.add_argument("-c", "--count", type=positive_int, help="Number of packets to capture")
    parser.add_argument(
        "-p",
        "--protocol",
        choices=["tcp", "udp", "icmp"],
        help="Optional protocol filter, converted into BPF syntax",
    )
    parser.add_argument("--port", type=port_number, help="Optional port filter, converted into BPF syntax")
    parser.add_argument("--bpf", help="Full BPF filter, for example: 'tcp and port 443'")
    parser.add_argument("-o", "--output", help="Save captured packet summaries to this file")
    parser.add_argument("--format", choices=["csv", "log"], default="csv", help="Export format for --output")
    parser.add_argument("--demo", action="store_true", help="Show sample output without live packet capture")
    return parser.parse_args()


def show_interfaces() -> int:
    for iface in list_interfaces():
        console.print(iface)
    return 0


def main() -> int:
    args = parse_args()

    try:
        if args.list_interfaces:
            return show_interfaces()

        if args.demo:
            rows = demo_packets()
            console.print("[bold cyan]Passive Network Packet Analyzer[/bold cyan]")
            console.print("Mode: [yellow]demo sample packets[/yellow]\n")
            print_packet_table(rows)
            print_statistics(rows)
            if args.output:
                exported_path = export_summaries(args.output, rows, args.format)
                console.print(f"\nSaved {len(rows)} packet summaries to [green]{exported_path}[/green]")
            return 0

        interface = validate_interface(args.interface)
        bpf_filter = build_bpf_filter(protocol=args.protocol, port=args.port, bpf=args.bpf)
        rows: list[PacketSummary] = []

        print_banner(interface, bpf_filter, args.count)

        def remember(summary: PacketSummary) -> None:
            rows.append(summary)

        capture_packets(interface=interface, count=args.count, bpf_filter=bpf_filter, on_packet=remember)

        print_packet_table(rows)
        print_statistics(rows)

        if args.output:
            exported_path = export_summaries(args.output, rows, args.format)
            console.print(f"\nSaved {len(rows)} packet summaries to [green]{exported_path}[/green]")

        return 0
    except KeyboardInterrupt:
        console.print("\n[yellow]Capture interrupted by user.[/yellow]")
        if "rows" in locals():
            print_packet_table(rows)
            print_statistics(rows)
            if args.output:
                exported_path = export_summaries(args.output, rows, args.format)
                console.print(f"\nSaved {len(rows)} packet summaries to [green]{exported_path}[/green]")
        return 130
    except Exception as exc:
        print_error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
