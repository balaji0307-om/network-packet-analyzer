# 🔍 Passive Network Packet Analyzer

<div align="center">

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Packet%20Engine-Scapy%202.5%2B-red.svg?logo=wireshark&logoColor=white)](https://scapy.net/)
[![Terminal UI](https://img.shields.io/badge/UI-Rich%20Terminal-green.svg)](https://github.com/Textualize/rich)
[![Tests](https://img.shields.io/badge/Unit%20Tests-17%20Passed-brightgreen.svg)](tests/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Type](https://img.shields.io/badge/Type-100%25%20Passive%20%2F%20Defensive-success.svg)]()
[![License](https://img.shields.io/badge/License-Educational%20%2F%20MIT-orange.svg)]()

**A production-grade, modular network packet capture and deep inspection analyzer built with Python, Scapy, and Rich.**
*Designed for defensive security monitoring, network forensics, protocol analysis, and cybersecurity education.*

[Key Features](#-key-features) • [Architecture](#-architecture--pipeline-design) • [Quick Start](#-installation--setup) • [Usage & CLI](#-cli-usage-reference) • [Verification](#-verification-evidence) • [Talking Points](#-internship--interview-talking-points)

</div>

---

> [!WARNING]
> **Authorization Disclaimer:** Use this tool **only** on networks and network interfaces you own or have explicit, documented authorization to monitor. Capturing network packets on unauthorized networks may violate local, national, and international cybersecurity laws.

> [!IMPORTANT]
> **Strictly Defensive Posture:** This application is strictly a **passive sniffer and protocol dissector**. The codebase contains **zero offensive capabilities** — no packet crafting (`IP()/TCP()`), injection (`send()`, `sendp()`), spoofing, port scanning, or active attack routines.

---

## 📋 Table of Contents

- [✨ Key Features](#-key-features)
- [📐 Architecture & Pipeline Design](#-architecture--pipeline-design)
- [🖥️ Operating System Prerequisites](#️-operating-system-prerequisites)
- [📦 Installation & Setup](#-installation--setup)
- [🚀 CLI Usage Reference](#-cli-usage-reference)
- [💡 Practical Command Recipes](#-practical-command-recipes)
- [📊 Terminal Output & Previews](#-terminal-output--previews)
- [📁 Multi-Format Export Specifications](#-multi-format-export-specifications)
- [🧪 Safe Local Testing Guide](#-safe-local-testing-guide)
- [⚡ Troubleshooting Guide](#-troubleshooting-guide)
- [🔬 Design Decisions: Scapy vs Raw Sockets](#-design-decisions-why-scapy-over-raw-sockets)
- [✅ Verification Evidence](#-verification-evidence)
- [🎓 Internship & Interview Talking Points](#-internship--interview-talking-points)
- [🛡️ Portfolio Distinction](#-portfolio-distinction)

---

## ✨ Key Features

- ⚡ **True Streaming Generator Pipeline:** Implements Scapy's asynchronous packet sniffer (`AsyncSniffer`) combined with Python's thread-safe `queue.Queue`. Packets are streamed one-by-one with `store=False`, preventing Scapy from accumulating captures in memory and keeping RAM usage strictly bounded.
- 🌐 **Multi-Layer Protocol Normalization:** Robust parsing across Layer 2 (Ethernet, ARP), Layer 3 (IPv4, IPv6), and Layer 4 (TCP, UDP, ICMP, ICMPv6).
- 🛡️ **Safe Payload Inspection & Privacy Mode:** Application-layer data is previewed as synchronized hexadecimal and safe ASCII (non-printable/control bytes replaced with dots). Truncation (`--payload-bytes`) prevents terminal overflow, while `--no-payload` suppresses extraction entirely for privacy.
- 🎯 **BPF Filtering:** Native support for Berkeley Packet Filter syntax (`-f "tcp port 443"`, `"udp port 53"`, `"icmp"`), delegated directly to the OS capture driver (Npcap / libpcap).
- 🎨 **Rich Terminal Dashboard:** Color-coded endpoints, protocol-specific highlights, visual distribution progress bars, and top-talker analytics rendered directly in the console.
- 💾 **Triple Export Engine:**
  - **CSV (`--csv`):** Structured, comma-separated values flushed row-by-row.
  - **JSON (`--json`):** Machine-readable JSON array for SIEM/log ingestion.
  - **PCAP (`--pcap`):** Raw, Wireshark-compatible packet captures for deep forensic analysis.
- 🔌 **Adaptive Interface Discovery:** Automatically detects active default adapters and seamlessly resolves friendly names (e.g. `"Wi-Fi"`), adapter indices (`0`, `1`), or Windows device GUIDs (`\Device\NPF_{...}`).
- 🛑 **Graceful Interrupt Handling:** Intercepting `Ctrl+C` cleanly renders session tables, outputs protocol metrics, and flushes all active file exporters without corrupting data.

---

## 📐 Architecture & Pipeline Design

The analyzer implements a clean, decoupled **unidirectional streaming pipeline**:

```text
       ┌────────────────────────────────────────────────────────┐
       │                analyzer/capture.py                     │
       │  • Interface auto-discovery & friendly name resolver   │
       │  • AsyncSniffer(store=False, prn=queue.put) (Thread)   │
       │  • live_capture() streaming generator                  │
       └───────────────────────────┬────────────────────────────┘
                                   │ Raw Scapy Packet (Streaming)
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │                 analyzer/parser.py                     │
       │  • parse_packet(packet, payload_bytes, no_payload)     │
       │  • Normalizes IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ARP  │
       │  • Generates safe hex + ASCII payload preview          │
       └───────────────────────────┬────────────────────────────┘
                                   │ Structured Record Dict
            ┌──────────────────────┼──────────────────────┐
            ▼                      ▼                      ▼
┌──────────────────────┐ ┌───────────────────┐ ┌──────────────────────┐
│  analyzer/display.py │ │  statistics.py    │ │ analyzer/exporter.py │
│  • PacketTable class │ │  PacketStatistics │ │ • CsvExporter        │
│  • Rich terminal UI  │ │  • Protocol share │ │ • JsonExporter       │
│  • Encoding-resilient│ │  • Distribution   │ │ • PcapExporter       │
│    tables            │ │  • Top-talker IPs │ │ (Incremental flush)  │
└──────────────────────┘ └───────────────────┘ └──────────────────────┘
```

### Module Responsibilities

| Module | Core Components | Function & Responsibility |
|---|---|---|
| `main.py` | CLI Controller | Argument parsing (`argparse`), input validation, banner display, interrupt traps (`Ctrl+C`), and pipeline coordination. |
| `analyzer/capture.py` | `live_capture()`, `get_interfaces()`, `validate_interface()` | Detects network adapters, auto-resolves friendly names, and runs background `AsyncSniffer` yielding packets via `queue.Queue`. Raises custom `CaptureError`. |
| `analyzer/parser.py` | `parse_packet()`, `_safe_ascii()` | Decodes packet headers across layers, extracts source/destination IPs and ports, packet length, and builds bounded hex + safe ASCII previews. |
| `analyzer/display.py` | `PacketTable`, `rprint()` | Renders responsive, color-coded terminal tables via Rich. Configured with UTF-8 fail-safes for Windows code pages. |
| `analyzer/statistics.py` | `PacketStatistics` | Calculates total packets, byte volume, protocol percentages with ASCII distribution bars, and top-talker source/destination hosts. |
| `analyzer/exporter.py` | `CsvExporter`, `JsonExporter`, `PcapExporter` | Streams summaries to disk (CSV/JSON) or raw frames (PCAP). Every record is flushed immediately to guarantee zero data loss. |

---

## 🖥️ Operating System Prerequisites

Raw packet capture requires lower-level network driver access on all platforms:

### 1. Windows
1. Download and install **[Npcap](https://npcap.com/#download)** (free for personal/educational use).
2. During setup, check **"Install Npcap in WinPcap API-compatible Mode"**.
3. Always run your terminal (PowerShell / Command Prompt) **as Administrator**.

### 2. Linux (Ubuntu / Debian / Fedora)
Install `libpcap` development libraries and `tcpdump`:
```bash
# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y libpcap-dev tcpdump

# Fedora / RHEL
sudo dnf install -y libpcap-devel tcpdump
```
Run with `sudo`, or grant packet-capture capabilities directly to your Python binary:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

### 3. macOS
macOS includes `libpcap` natively. Execute with elevated privileges:
```bash
sudo python3 main.py -c 20
```

---

## 📦 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/balaji0307-om/network-packet-analyzer.git
cd network-packet-analyzer
```

### 2. Create & Activate a Virtual Environment
```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

`requirements.txt` specifies:
```text
scapy>=2.5,<3
rich>=13,<15
```

---

## 🚀 CLI Usage Reference

```text
usage: network-packet-analyzer [-h] [-i INTERFACE] [--list-interfaces]
                               [-f BPF_FILTER] [-c COUNT] [--csv FILE]
                               [--json FILE] [--pcap FILE]
                               [--payload-bytes PAYLOAD_BYTES] [--no-payload]
```

### CLI Flag Reference

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--interface` | `-i` | String | Auto-detected | Adapter name (`"Wi-Fi"`), index (`0`), or device GUID string. |
| `--list-interfaces` | — | Flag | N/A | Prints detected network adapters with indices, IPs, and exits. |
| `--filter` | `-f` | String | None | Berkeley Packet Filter (BPF) string (e.g. `"tcp port 443"`). |
| `--count` | `-c` | Integer | `0` (unlimited) | Number of packets to capture (`0` captures until `Ctrl+C`). Must be >= 0. |
| `--csv` | — | Path | None | File path for incremental CSV summaries. |
| `--json` | — | Path | None | File path for incremental JSON array summaries. |
| `--pcap` | — | Path | None | File path for raw PCAP capture (Wireshark-compatible). |
| `--payload-bytes` | — | Integer | `32` | Maximum payload preview bytes (hex and ASCII). Must be >= 0. |
| `--no-payload` | — | Flag | `False` | Privacy mode: completely omits application payload extraction. |
| `--help` | `-h` | Flag | N/A | Displays full usage information and practical examples. |

---

## 💡 Practical Command Recipes

### 1. Identify Available Interfaces
```bash
python main.py --list-interfaces
```

### 2. Basic Capture (Auto-detecting Active Adapter)
```bash
python main.py -c 25
```

### 3. Capture on a Specific Interface
```bash
# Windows (friendly name or index)
python main.py -i "Wi-Fi" -c 50
python main.py -i 0 -c 50

# Linux
sudo python main.py -i eth0 -c 50
```

### 4. Berkeley Packet Filters (BPF) Examples

```bash
# Capture only TCP traffic
python main.py -i "Wi-Fi" -f "tcp" -c 30

# Inspect DNS queries and responses
python main.py -i "Wi-Fi" -f "udp port 53" -c 20

# Filter ICMP (ping) packets
python main.py -i "Wi-Fi" -f "icmp" -c 10

# Capture secure web traffic (HTTPS)
python main.py -i "Wi-Fi" -f "tcp port 443" -c 40

# Monitor communications with a specific host
python main.py -i "Wi-Fi" -f "host 192.168.1.1 and tcp" -c 25
```

### 5. Multi-Format Forensic Export
Capture 100 packets, simultaneously recording structured CSV summaries, structured JSON, and raw PCAP frames:
```bash
python main.py -i "Wi-Fi" -c 100 --csv exports/session.csv --json exports/session.json --pcap exports/session.pcap
```

### 6. Privacy Mode & Custom Payload Previews
```bash
# Completely omit payload inspection (privacy compliant)
python main.py -c 50 --no-payload

# Extend payload inspection to 64 bytes
python main.py -c 50 --payload-bytes 64
```

---

## 📊 Terminal Output & Previews

### Live Progress Stream & Packet Table
```text
+------------------------------------------+
|   Passive Network Packet Analyzer        |
+------------------------------------------+
  Interface:  \Device\NPF_{0E8596C2-9F5B-41F4-BB84-1FD792F32B39}
  BPF Filter: tcp
  Target:     5 packets
  Mode:       PASSIVE monitoring only

Capturing packets... press Ctrl+C to stop

  #1    TCP    172.25.68.68:55654 -> 172.217.114.4:443 (106 bytes)
  #2    TCP    172.25.68.68:55654 -> 172.217.114.4:443 (1466 bytes)
  #3    TCP    172.25.68.68:55654 -> 172.217.114.4:443 (1466 bytes)
  #4    TCP    172.25.68.68:55654 -> 172.217.114.4:443 (1466 bytes)
  #5    TCP    172.25.68.68:55654 -> 172.217.114.4:443 (1466 bytes)

                                      Captured Packets                                       
┌───┬─────────────────────────┬────────────────────┬───────────────────┬──────────┬────────┬─────────────────────────────┐
│ # │ Timestamp               │ Source             │ Destination       │ Protocol │ Length │ Payload Preview             │
├───┼─────────────────────────┼────────────────────┼───────────────────┼──────────┼────────┼─────────────────────────────┤
│ 1 │ 2026-09-08 15:29:26.356 │ 172.25.68.68:55654 │ 172.217.114.4:443 │   TCP    │    106 │ 17 03 03 00 2f 48 45 bb ... │
│   │                         │                    │                   │          │        │ | ..../HE.d.O3....s.De...   │
│ 2 │ 2026-09-08 15:29:26.356 │ 172.25.68.68:55654 │ 172.217.114.4:443 │   TCP    │   1466 │ 17 03 03 40 11 01 84 89 ... │
│   │                         │                    │                   │          │        │ | ...@.....#.........vq.k..│
└───┴─────────────────────────┴────────────────────┴───────────────────┴──────────┴────────┴─────────────────────────────┘
```

### Protocol Distribution & Top Talkers
```text
=== Capture Statistics ===
  Total packets captured: 20
  Total bytes captured:   2,645

                Protocol Breakdown                
┌──────────┬─────────┬────────────┬──────────────┐
│ Protocol │ Packets │ Percentage │ Distribution │
├──────────┼─────────┼────────────┼──────────────┤
│ TCP      │       8 │      40.0% │ [######------]│
│ ARP      │       5 │      25.0% │ [####--------]│
│ UDP      │       4 │      20.0% │ [###---------]│
│ ICMPv6   │       2 │      10.0% │ [##----------]│
│ IPv6/0   │       1 │       5.0% │ [#-----------]│
└──────────┴─────────┴────────────┴──────────────┘

             Top Source IPs             
┌───────────────────────────┬─────────┬────────────┐
│ IP Address                │ Packets │ Percentage │
├───────────────────────────┼─────────┼────────────┤
│ 172.217.114.4             │       5 │      25.0% │
│ fe80::aa8d:f3b0:8004:2c6d │       4 │      20.0% │
│ 172.25.68.68              │       3 │      15.0% │
└───────────────────────────┴─────────┴────────────┘
```

---

## 📁 Multi-Format Export Specifications

All exporters operate incrementally with real-time file flushing (`flush()`). Data is preserved even if the process is terminated abruptly or stopped via `Ctrl+C`.

### 1. CSV Schema (`--csv exports/capture.csv`)

| Column | Type | Description | Sample Value |
|---|---|---|---|
| `timestamp` | String | ISO formatted capture timestamp (`YYYY-MM-DD HH:MM:SS.mmm`) | `2026-09-08 15:30:10.273` |
| `src_ip` | String | Source IP address (IPv4, IPv6, or MAC fallback) | `172.25.68.68` |
| `dst_ip` | String | Destination IP address (IPv4, IPv6, or MAC fallback) | `172.217.114.4` |
| `src_port` | String | Transport layer source port (or `-` if inapplicable) | `55654` |
| `dst_port` | String | Transport layer destination port (or `-` if inapplicable) | `443` |
| `protocol` | String | Normalized protocol (`TCP`, `UDP`, `ICMP`, `ICMPv6`, `ARP`) | `TCP` |
| `length` | Integer | Total frame wire length in bytes | `1466` |
| `payload_hex` | String | Bounded hex representation of payload | `17 03 03 40 11 ...` |
| `payload_ascii` | String | Safe ASCII preview (non-printable chars replaced with `.`) | `...@...|#....e~\...` |

### 2. JSON Array Schema (`--json exports/capture.json`)
```json
[
  {
    "timestamp": "2026-09-08 15:30:10.273",
    "src_ip": "172.25.68.68",
    "dst_ip": "172.217.114.4",
    "src_port": "55654",
    "dst_port": "443",
    "protocol": "TCP",
    "length": 1466,
    "payload_hex": "17 03 03 40 11 ...",
    "payload_ascii": "...@...|#....e~\\..."
  }
]
```

### 3. PCAP Binary Dump (`--pcap exports/session.pcap`)
Writes raw packet frames directly using Scapy's `PcapWriter(sync=True)`. Can be opened immediately in **Wireshark**, **NetworkMiner**, or processed via `tcpdump -r session.pcap`.

---

## 🧪 Safe Local Testing Guide

Generate harmless local traffic to verify filtering and dissection without exposing sensitive external credentials:

### 1. HTTP Traffic (TCP Port 8080)
```bash
# Terminal 1: Launch temporary Python HTTP server
python -m http.server 8080

# Terminal 2: Run packet analyzer targeting port 8080
python main.py -f "tcp port 8080" -c 10

# Terminal 3: Generate traffic
curl http://localhost:8080
```

### 2. DNS Query Traffic (UDP Port 53)
```bash
# Terminal 1: Monitor DNS queries
python main.py -f "udp port 53" -c 5

# Terminal 2: Trigger resolution
nslookup example.com
```

### 3. ICMP Ping Traffic
```bash
# Terminal 1: Monitor ICMP
python main.py -f "icmp" -c 4

# Terminal 2: Send ping
ping 127.0.0.1
```

---

## ⚡ Troubleshooting Guide

| Issue / Error Message | Root Cause | Solution |
|---|---|---|
| `CaptureError: Permission denied: packet capture requires elevated privileges` | Lower-level socket access denied by OS. | **Windows:** Run terminal as Administrator.<br>**Linux:** Prepend command with `sudo`. |
| `CaptureError: Scapy is not installed` | Missing virtual environment dependencies. | Run `pip install -r requirements.txt`. |
| `CaptureError: Interface '<name>' not found` | Mismatched interface string. | Run `python main.py --list-interfaces` and use the exact index or friendly name. |
| `No network interfaces found` | Missing capture driver on host. | **Windows:** Install [Npcap](https://npcap.com/) with WinPcap API compatibility mode.<br>**Linux:** Install `libpcap-dev`. |
| Empty payload on HTTPS traffic | Payload is TLS/SSL encrypted. | Expected behavior. Encrypted application-layer data renders as ciphertext bytes. |

---

## 🔬 Design Decisions: Why Scapy over Raw Sockets?

| Dimension | Standard Raw Sockets (`socket.SOCK_RAW`) | Scapy Engine (`AsyncSniffer`) |
|---|---|---|
| **OS Portability** | Highly OS-dependent; Windows restricts non-admin raw sockets and blocks raw TCP capture entirely. | Unified cross-platform API across Windows (Npcap), Linux (libpcap), and macOS. |
| **Layer 2 Visibility** | Cannot capture Layer 2 Ethernet frames or ARP packets on standard Windows sockets. | Direct access to Layer 2 Ethernet frames, ARP headers, 802.1Q VLAN tags, and loopback. |
| **Filter Performance** | Filtering must be performed in userland Python bytecode after reading every frame. | **BPF filtering is delegated to the libpcap/Npcap capture backend**, reducing packets delivered to Python when supported by the capture stack. |
| **Protocol Dissection** | Requires manual, error-prone `struct.unpack` decoding for each protocol option. | Comprehensive parsing library decoding 500+ network protocols out of the box. |

---

## ✅ Verification Evidence

The implementation has been thoroughly verified through automated testing and live hardware validation:

```bash
python -m unittest discover tests
```
```text
Ran 17 tests in 0.045s

OK
```

### Verified Scenarios:
- [x] **17 Automated Unit Tests Passed:** Full coverage of `parse_packet`, IPv4, IPv6, TCP, UDP, ICMP, ARP, payload truncation, `--no-payload`, `PacketStatistics`, `CsvExporter`, `JsonExporter`, `PcapExporter`, `PacketTable`, and interface resolution.
- [x] **Live Wi-Fi Capture Confirmed:** Successfully captured and parsed live frames on active wireless adapter (`Realtek 8821CE Wireless LAN`).
- [x] **BPF Filtering Tested:** Verified `tcp`, `udp`, and `icmp` filters isolate matching traffic with zero leakage.
- [x] **Multi-Export Validated:** Verified incremental output generation across `.csv`, `.json`, and `.pcap`.
- [x] **Encoding Safety:** Tested on Windows console code pages (cp1252/UTF-8) with zero `UnicodeEncodeError` exceptions.

---

## 🎓 Internship & Interview Talking Points

- **Asynchronous Producer-Consumer Architecture:**  
  *"Rather than blocking the main thread or reading packets in a tight `sniff(count=1)` loop, I decoupled capture from analysis. `AsyncSniffer` runs in a background thread and deposits incoming frames into a thread-safe `queue.Queue`. The `live_capture()` generator pulls from this queue and streams packets one-by-one to the normalizer and display. Using `store=False` prevents Scapy from retaining captures in an internal list, keeping memory usage bounded by the application pipeline."*

- **Defensive & Passive Engineering:**  
  *"In security operations, visibility must never introduce collateral disruption. The analyzer is purely passive: it never crafts (`IP()/TCP()`), transmits (`send()`), or injects packets into the wire. All payload views are sanitized by replacing non-printable control characters with dots, protecting the analyst's terminal emulator from escape-sequence attacks."*

- **Defensive Error Handling:**  
  *"Instead of leaking unhandled OS tracebacks, the system traps platform permissions, interface resolution errors, and driver exceptions into a custom `CaptureError` with actionable remediation guidance."*

---

## 🛡️ Portfolio Distinction

To maintain a focused, high-impact cybersecurity portfolio, keep your network visibility and intrusion detection projects separate:

| Dimension | Project 1: Network Packet Analyzer (This Repo) | Project 2: Network Intrusion Detection System (NIDS) |
|---|---|---|
| **Core Role** | Network Visibility, Protocol Dissection, Traffic Auditing | Signature Matching, Anomaly Detection, Alerting |
| **Technology Stack**| Python, Scapy (`AsyncSniffer`), Rich, Npcap / libpcap | Suricata Engine, Custom IDS Rules, EVE JSON, Streamlit |
| **Data Handled** | Raw packets, headers, payload previews, protocol ratios | Alert events, threat classifications, severity scores |
| **Target Job Profile** | Network Security Analyst / Protocol Engineer / Forensics | SOC Analyst / Blue Team / Threat Detection Engineer |

---

## 📄 License & Ethical Terms

This project is open-source under the **MIT License**. Distributed solely for authorized network analysis, security research, and educational purposes.
