# Network Packet Analyzer

A Python-based passive Network Packet Analyzer built for cybersecurity internship submission work. The tool captures live packets with Scapy, parses useful packet metadata, displays readable terminal tables, exports packet summaries, and shows basic traffic statistics.

This is a defensive monitoring and learning tool only. It does not perform scanning, spoofing, packet injection, exploitation, or any active attack behavior.

## Features

- Live packet capture using Scapy
- Automatic network interface detection
- Manual network interface selection
- Optional BPF filters for protocol and port filtering
- Supports common protocols such as TCP, UDP, ICMP, ARP, IPv4, and IPv6
- Clean terminal table output using Rich
- Safe truncated payload preview in both hex and ASCII
- CSV and log file export
- End-of-capture statistics:
  - Total packets captured
  - Protocol breakdown
  - Top talkers by IP address
- Demo mode for environments where live packet capture is not available
- Modular code structure for easier review and maintenance
- Error handling for missing dependencies, invalid interfaces, and permission issues

## Tech Stack

- Python 3
- Scapy
- Rich
- Npcap on Windows or libpcap on Linux/macOS

## Project Structure

```text
network-packet-analyzer/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
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

## File Overview

- `main.py` - command-line entry point
- `packet_analyzer/capture.py` - live packet capture using Scapy
- `packet_analyzer/parser.py` - extracts timestamp, IPs, ports, protocol, length, and payload preview
- `packet_analyzer/display.py` - terminal table rendering
- `packet_analyzer/export.py` - CSV and log export
- `packet_analyzer/stats.py` - packet statistics and top talkers
- `packet_analyzer/interfaces.py` - interface listing, validation, and auto-detection
- `packet_analyzer/demo.py` - safe demo packets for testing without live capture
- `packet_analyzer/models.py` - packet summary data model

## Requirements

- Python 3.10 or newer
- Administrator/root privileges for live packet capture
- Npcap on Windows
- libpcap on Linux/macOS

On Windows, install Npcap from:

```text
https://npcap.com/
```

During installation, enable WinPcap API-compatible mode if available.

## Installation

Clone the repository:

```bash
git clone https://github.com/balaji0307-om/network-packet-analyzer.git
cd network-packet-analyzer
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Show help:

```bash
python main.py --help
```

List available network interfaces:

```bash
python main.py --list-interfaces
```

Capture 25 packets using the auto-detected interface:

```bash
python main.py --count 25
```

Capture packets from a specific interface:

```bash
python main.py --interface "\Device\NPF_{YOUR-INTERFACE-ID}" --count 25
```

Capture TCP packets only:

```bash
python main.py --protocol tcp --count 25
```

Capture UDP packets only:

```bash
python main.py --protocol udp --count 25
```

Capture ICMP packets only:

```bash
python main.py --protocol icmp --count 10
```

Capture packets for a specific port:

```bash
python main.py --port 443 --count 25
```

Use a custom BPF filter:

```bash
python main.py --bpf "tcp and port 443" --count 25
```

Save captured packet summaries to CSV:

```bash
python main.py --count 25 --output final_capture.csv
```

Save captured packet summaries to a log file:

```bash
python main.py --count 25 --output capture.log --format log
```

Run demo mode without live packet capture:

```bash
python main.py --demo
```

Export demo packet summaries:

```bash
python main.py --demo --output demo_capture.csv
```

## Sample Output

```text
Passive Network Packet Analyzer
Interface: \Device\NPF_{...}
BPF filter: none
Capture target: 25

Captured Packet Summaries
Timestamp                Source              Destination     Protocol  Length  Payload Preview
2026-08-30 22:06:22.839  172.20.8.186:60375  103.3.33.9:80  TCP       165     47 45 54 ... | GET /...

Capture Statistics
Total packets: 25

Protocol Breakdown
TCP: 21
UDP: 3

Top Talkers by IP
172.20.8.186
103.3.33.9
```

## Export Format

CSV exports include:

- Timestamp
- Source IP
- Destination IP
- Source port
- Destination port
- Protocol
- Packet length
- Payload preview in hex
- Payload preview in ASCII

## Permission Notes

Live packet capture usually requires elevated privileges.

Windows:

```text
Run PowerShell or Command Prompt as Administrator.
```

Linux/macOS:

```bash
sudo python main.py --count 25
```

If permissions are missing, Scapy may raise packet capture or raw socket errors.

## Raw Socket Fallback Note

Scapy is used as the primary capture engine because it provides packet capture, protocol parsing, and BPF filtering support through pcap/Npcap. If Scapy is unavailable, Python raw sockets can be used as a limited fallback approach, but raw sockets are platform-specific, require elevated privileges, and provide less protocol decoding support than Scapy.

## Security and Ethics

Use this analyzer only on networks and systems where you have permission. The project is intended for:

- Cybersecurity learning
- Defensive monitoring
- Packet inspection
- Troubleshooting
- Internship demonstration

It is not intended for unauthorized monitoring or offensive activity.

## Repository

```text
https://github.com/balaji0307-om/network-packet-analyzer
```
