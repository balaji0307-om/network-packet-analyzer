"""CSV exporter for packet summaries.

Provides the CsvExporter class that writes parsed packet records to a CSV
file incrementally (one row per packet as they are captured). Only summary
metadata is exported — never raw packet bytes or full payloads.

The exporter is designed to be used as a context manager or with explicit
open/close calls, ensuring the CSV file is properly flushed and closed
even if the capture is interrupted by Ctrl+C.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Optional, TextIO


# CSV column headers matching the keys from parser.parse_packet()
CSV_FIELDS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "length",
    "payload_hex",
    "payload_ascii",
]


class CsvExporter:
    """Incrementally writes packet summary records to a CSV file.

    Each call to write_record() appends one row and flushes immediately,
    so data is preserved even if the process is interrupted.

    Usage:
        exporter = CsvExporter("capture.csv")
        exporter.open()
        exporter.write_record(parsed_record)
        exporter.close()  # Always call close, e.g. in a finally block

    Or as a context manager:
        with CsvExporter("capture.csv") as exporter:
            exporter.write_record(parsed_record)
    """

    def __init__(self, filepath: str) -> None:
        """Initialize the CSV exporter.

        Args:
            filepath: Path to the output CSV file. Parent directories
                      will be created if they don't exist.
        """
        self._path = Path(filepath).expanduser().resolve()
        self._file: Optional[TextIO] = None
        self._writer: Optional[csv.DictWriter] = None
        self._row_count: int = 0

    @property
    def filepath(self) -> Path:
        """The resolved output file path."""
        return self._path

    @property
    def row_count(self) -> int:
        """Number of records written so far."""
        return self._row_count

    def open(self) -> None:
        """Open the CSV file and write the header row."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._path.open("w", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._file, fieldnames=CSV_FIELDS)
        self._writer.writeheader()
        self._file.flush()

    def write_record(self, record: dict) -> None:
        """Write a single packet record to the CSV file.

        Args:
            record: A dict as returned by parser.parse_packet().
                    Only keys matching CSV_FIELDS are written.

        Raises:
            RuntimeError: If the exporter has not been opened yet.
        """
        if self._writer is None or self._file is None:
            raise RuntimeError(
                "CsvExporter is not open. Call open() or use as a context manager."
            )

        row = {field: record.get(field, "") for field in CSV_FIELDS}
        self._writer.writerow(row)
        self._file.flush()  # Flush after every write for crash safety
        self._row_count += 1

    def close(self) -> None:
        """Close the CSV file. Safe to call multiple times."""
        if self._file is not None and not self._file.closed:
            self._file.flush()
            self._file.close()

    def __enter__(self) -> CsvExporter:
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


import json

try:
    from scapy.utils import PcapWriter
except ImportError:
    PcapWriter = None


class JsonExporter:
    """Incrementally writes packet summary records to a JSON array file."""

    def __init__(self, filepath: str) -> None:
        self._path = Path(filepath).expanduser().resolve()
        self._file: Optional[TextIO] = None
        self._row_count: int = 0

    @property
    def filepath(self) -> Path:
        return self._path

    @property
    def row_count(self) -> int:
        return self._row_count

    def open(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._path.open("w", encoding="utf-8")
        self._file.write("[\n")
        self._file.flush()

    def write_record(self, record: dict) -> None:
        if self._file is None or self._file.closed:
            raise RuntimeError("JsonExporter is not open.")
        prefix = ",\n" if self._row_count > 0 else ""
        item = {field: record.get(field, "") for field in CSV_FIELDS}
        self._file.write(prefix + "  " + json.dumps(item, ensure_ascii=False))
        self._file.flush()
        self._row_count += 1

    def close(self) -> None:
        if self._file is not None and not self._file.closed:
            self._file.write("\n]\n")
            self._file.flush()
            self._file.close()

    def __enter__(self) -> JsonExporter:
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class PcapExporter:
    """Incrementally saves raw captured packets into a standard PCAP file."""

    def __init__(self, filepath: str) -> None:
        self._path = Path(filepath).expanduser().resolve()
        self._writer = None
        self._count: int = 0

    @property
    def filepath(self) -> Path:
        return self._path

    @property
    def row_count(self) -> int:
        return self._count

    def open(self) -> None:
        if PcapWriter is None:
            raise RuntimeError("Scapy is required for PCAP export.")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._writer = PcapWriter(str(self._path), append=True, sync=True)

    def write_packet(self, packet: object) -> None:
        if self._writer is None:
            raise RuntimeError("PcapExporter is not open.")
        self._writer.write(packet)
        self._count += 1

    def close(self) -> None:
        if self._writer is not None:
            self._writer.flush()
            self._writer.close()

    def __enter__(self) -> PcapExporter:
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
