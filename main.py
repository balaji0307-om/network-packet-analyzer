#!/usr/bin/env python3
"""Network Packet Analyzer — CLI entry point.

A passive, modular network packet capture and analysis tool built with
Scapy and Rich. Designed for authorized network monitoring and security
learning only — no packet injection or active attack functionality.

Usage:
    python main.py --list-interfaces
    python main.py -i eth0 -c 50 -f "tcp port 443"
    python main.py --csv capture.csv --count 100
    python main.py -f "udp port 53" --payload-bytes 64
    python main.py --no-payload -c 20
"""

from __future__ import annotations

import argparse
import signal
import sys

# Ensure UTF-8 console output on Windows
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

from analyzer.capture import (
    CaptureError,
    get_interfaces,
    live_capture,
    validate_interface,
)
from analyzer.parser import parse_packet
from analyzer.display import PacketTable, rprint
from analyzer.statistics import PacketStatistics
from analyzer.exporter import CsvExporter, JsonExporter, PcapExporter


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser with all CLI options."""
    parser = argparse.ArgumentParser(
        prog="network-packet-analyzer",
        description=(
            "Passive Network Packet Analyzer — capture and analyze live network "
            "traffic using Scapy. Strictly passive: no packet injection, spoofing, "
            "or scanning capabilities."
        ),
        epilog=(
            "Examples:\n"
            "  python main.py --list-interfaces\n"
            "  python main.py -i eth0 -c 50\n"
            '  python main.py -f "tcp port 443" --csv output.csv\n'
            '  python main.py -f "udp port 53" --payload-bytes 64\n'
            "  python main.py --no-payload -c 20\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Interface selection
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on (auto-detected if omitted)",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit",
    )

    # Capture control
    parser.add_argument(
        "-f", "--filter",
        dest="bpf_filter",
        help='BPF filter string (e.g. "tcp", "udp port 53", "icmp")',
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited, stop with Ctrl+C)",
    )

    # Export
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Export packet summaries to a CSV file incrementally",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Export packet summaries to a JSON file incrementally",
    )
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        help="Save raw captured packets to a PCAP file (Wireshark-compatible)",
    )

    # Payload options
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=32,
        help="Number of payload bytes to show in hex+ASCII preview (default: 32)",
    )
    parser.add_argument(
        "--no-payload",
        action="store_true",
        help="Disable payload capture entirely (privacy mode)",
    )

    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validate CLI arguments and print clean error messages.

    Raises:
        SystemExit: If validation fails (with a user-friendly message).
    """
    if args.count < 0:
        rprint("[bold red]Error:[/bold red] --count must be >= 0 (got {0})".format(args.count))
        sys.exit(1)

    if args.payload_bytes < 0:
        rprint("[bold red]Error:[/bold red] --payload-bytes must be >= 0 (got {0})".format(args.payload_bytes))
        sys.exit(1)


def show_interfaces() -> None:
    """Print all available network interfaces and exit."""
    rprint("\n[bold cyan]Available Network Interfaces[/bold cyan]")
    rprint("-" * 40)
    for iface in get_interfaces():
        rprint(f"  * {iface}")
    rprint("")


def print_banner(interface: str, bpf_filter: str | None, count: int) -> None:
    """Print a capture session banner with configuration details."""
    rprint("\n[bold cyan]+------------------------------------------+[/bold cyan]")
    rprint("[bold cyan]|   Passive Network Packet Analyzer        |[/bold cyan]")
    rprint("[bold cyan]+------------------------------------------+[/bold cyan]")
    rprint(f"  Interface:  [green]{interface}[/green]")
    rprint(f"  BPF Filter: [yellow]{bpf_filter or 'none (all traffic)'}[/yellow]")
    target = str(count) if count > 0 else "unlimited (Ctrl+C to stop)"
    rprint(f"  Target:     [yellow]{target} packets[/yellow]")
    rprint("  Mode:       [green]PASSIVE monitoring only[/green]")
    rprint("")


def main() -> int:
    """Main entry point for the Network Packet Analyzer.

    Returns:
        Exit code: 0 for success, 1 for errors, 130 for Ctrl+C interrupt.
    """
    parser = build_parser()
    args = parser.parse_args()

    # --- Validate arguments ---
    validate_args(args)

    try:
        # --- List interfaces mode ---
        if args.list_interfaces:
            show_interfaces()
            return 0

        # --- Resolve interface ---
        interface = validate_interface(args.interface)

        # --- Print capture banner ---
        print_banner(interface, args.bpf_filter, args.count)

        # --- Initialize components ---
        packet_table = PacketTable()
        stats = PacketStatistics()
        csv_exporter: CsvExporter | None = None
        json_exporter: JsonExporter | None = None
        pcap_exporter: PcapExporter | None = None

        if args.csv:
            csv_exporter = CsvExporter(args.csv)
            csv_exporter.open()
            rprint(f"  CSV export:  [green]{csv_exporter.filepath}[/green]")

        if args.json:
            json_exporter = JsonExporter(args.json)
            json_exporter.open()
            rprint(f"  JSON export: [green]{json_exporter.filepath}[/green]")

        if args.pcap:
            pcap_exporter = PcapExporter(args.pcap)
            pcap_exporter.open()
            rprint(f"  PCAP export: [green]{pcap_exporter.filepath}[/green]")

        if args.csv or args.json or args.pcap:
            rprint("")

        try:
            # --- Capture loop ---
            rprint("[dim]Capturing packets... press Ctrl+C to stop[/dim]\n")

            for raw_packet in live_capture(
                interface=interface,
                bpf_filter=args.bpf_filter,
                count=args.count,
            ):
                # Parse the raw packet into a structured record
                record = parse_packet(
                    raw_packet,
                    payload_bytes=args.payload_bytes,
                    no_payload=args.no_payload,
                )

                # Feed the record to all pipeline components
                packet_table.add_packet(record)
                stats.update(record)

                if csv_exporter:
                    csv_exporter.write_record(record)

                if json_exporter:
                    json_exporter.write_record(record)

                if pcap_exporter:
                    pcap_exporter.write_packet(raw_packet)

                # Print a live progress indicator
                src = record['src_ip']
                dst = record['dst_ip']
                proto = record['protocol']
                rprint(
                    f"  [dim]#{packet_table.count}[/dim] "
                    f"[cyan]{proto:<6}[/cyan] {src} -> {dst} "
                    f"[dim]({record['length']} bytes)[/dim]"
                )

        except KeyboardInterrupt:
            rprint("\n[yellow][!] Capture interrupted by user (Ctrl+C)[/yellow]")

        finally:
            # --- Always render results, even after Ctrl+C ---
            rprint("")
            packet_table.render()
            stats.render()

            if csv_exporter:
                csv_exporter.close()
                rprint(
                    f"\n[green][+] Exported {csv_exporter.row_count} packet summaries "
                    f"to {csv_exporter.filepath}[/green]"
                )

            if json_exporter:
                json_exporter.close()
                rprint(
                    f"[green][+] Exported {json_exporter.row_count} packet summaries "
                    f"to {json_exporter.filepath}[/green]"
                )

            if pcap_exporter:
                pcap_exporter.close()
                rprint(
                    f"[green][+] Saved {pcap_exporter.row_count} raw packets "
                    f"to {pcap_exporter.filepath}[/green]"
                )

            rprint("")

        return 0

    except CaptureError as exc:
        rprint(f"\n[bold red]Capture Error:[/bold red] {exc}")
        return 1

    except Exception as exc:
        rprint(f"\n[bold red]Error:[/bold red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
