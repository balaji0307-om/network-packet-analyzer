# Network Packet Analyzer

A passive, defensive network packet analyzer built in Python for cybersecurity learning and internship submission work. It uses Scapy to capture live packets, parses common protocols, displays packet summaries in a clean terminal table, and can export results for later review.

This tool does not perform active scanning, spoofing, injection, exploitation, or attacks.

## Features

- Live packet capture with Scapy
- Safe demo mode for environments where Npcap/libpcap is not installed yet
- Manual interface selection or best-effort auto-detection
- Optional BPF capture filters, including protocol and port filters
- Packet summary table with timestamp, IPs, ports, protocol, length, and safe payload preview
- CSV or plain log export
- End-of-run statistics:
  - Total packets
  - Protocol breakdown
  - Top talkers by IP
- Modular code layout for capture, parsing, display, export, and statistics
- Defensive error handling for missing privileges, invalid interfaces, and missing dependencies

## Requirements

- Python 3.10+
- Administrator/root privileges for live packet capture
- Scapy
- Rich
- Packet capture driver/library:
  - Windows: install [Npcap](https://npcap.com/) with WinPcap-compatible mode enabled
  - Linux/macOS: libpcap is normally available through the OS package manager

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Usage

List available interfaces:

```bash
python main.py --list-interfaces
```

Capture 25 packets using auto-detected interface:

```bash
python main.py --count 25
```

Capture TCP packets only:

```bash
python main.py --protocol tcp --count 50
```

Capture traffic for a specific port:

```bash
python main.py --port 443 --count 50
```

Use a full BPF filter:

```bash
python main.py --bpf "tcp and port 443" --count 50
```

Save packet summaries to CSV:

```bash
python main.py --count 100 --output captures.csv
```

Run a safe local demo without live packet capture access:

```bash
python main.py --demo
```

Export demo packet summaries:

```bash
python main.py --demo --output demo_capture.csv
```

Save packet summaries to a plain log file:

```bash
python main.py --count 100 --output captures.log --format log
```

Capture until interrupted with `Ctrl+C`:

```bash
python main.py
```

## Permissions

Live packet capture usually requires elevated privileges:

- Windows: run PowerShell or Command Prompt as Administrator
- Linux/macOS: run with `sudo`, or configure packet capture capabilities for your Python interpreter

If permissions are missing, Scapy may raise errors related to raw sockets or packet capture access.

## Raw Socket Fallback Note

Scapy is the primary capture engine for this project because it provides portable packet capture and protocol parsing on top of pcap/Npcap. If Scapy is unavailable, a limited fallback could be implemented with Python raw sockets, but raw sockets are platform-specific, require elevated privileges, and do not provide Scapy's rich protocol dissection. For a cybersecurity internship submission, Scapy remains the recommended and safer passive-monitoring approach.

## Project Structure

```text
network-packet-analyzer/
├── main.py
├── requirements.txt
├── README.md
└── packet_analyzer/
    ├── __init__.py
    ├── capture.py
    ├── demo.py
    ├── display.py
    ├── export.py
    ├── interfaces.py
    ├── models.py
    ├── parser.py
    └── stats.py
```

## Ethics

Only capture traffic on networks and systems where you have permission. This project is intended for passive monitoring, education, troubleshooting, and defensive analysis.
