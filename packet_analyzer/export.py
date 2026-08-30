from __future__ import annotations

import csv
from pathlib import Path

from .models import PacketSummary


CSV_FIELDS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "length",
    "payload_hex",
    "payload_ascii",
]


def export_csv(path: Path, rows: list[PacketSummary]) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: getattr(row, field) for field in CSV_FIELDS})


def export_log(path: Path, rows: list[PacketSummary]) -> None:
    with path.open("w", encoding="utf-8") as file:
        for row in rows:
            file.write(
                f"{row.timestamp} {row.protocol} "
                f"{row.source_ip}:{row.source_port} -> {row.destination_ip}:{row.destination_port} "
                f"len={row.length} payload={row.payload_preview()}\n"
            )


def export_summaries(path: str, rows: list[PacketSummary], output_format: str) -> Path:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "csv":
        export_csv(destination, rows)
    elif output_format == "log":
        export_log(destination, rows)
    else:
        raise ValueError(f"Unsupported export format: {output_format}")

    return destination
