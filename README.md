# 🔍 Network Packet Analyzer

A **passive, modular** network packet capture and analysis tool built in Python with **Scapy** and **Rich**. Designed for cybersecurity learning and authorized network monitoring.

> ⚠️ **Authorization Disclaimer:** Use only on networks/interfaces you own or are explicitly authorized to monitor. Unauthorized network packet inspection may violate local, national, and international laws.
>
> 🛡️ **Passive-Only Statement:** This tool is strictly defensive. The analyzer does not inject packets, perform scanning, spoofing, exploitation, or active attacks anywhere in the codebase.

### ✅ Verification Evidence
- [x] **Automated tests:** 17 passed (`python -m unittest discover tests`)
- [x] **Live Wi-Fi capture:** verified (streamed packets via `AsyncSniffer` + Queue)
- [x] **BPF filtering:** verified (`tcp`, `udp`, `icmp`, port rules tested and confirmed)
- [x] **CSV export:** verified (`exports/capture.csv` incremental flush)
- [x] **JSON export:** verified (`exports/capture.json` structured records)
- [x] **PCAP export:** verified (`exports/session.pcap` Wireshark-compatible dump)

---

## 📐 Architecture & Pipeline Design

The analyzer implements a clean **unidirectional data pipeline** where each module has a single, well-defined responsibility:

```
┌────────────────────────────────┐
│      analyzer/capture.py       │  Interface detection & validation
│   live_capture() (generator)   │  Passive packet capture via Scapy AsyncSniffer
└───────────────┬────────────────┘
                │ Raw Scapy Packet Objects (streamed 1-by-1)
                ▼
┌────────────────────────────────┐
│      analyzer/parser.py        │  Normalizes TCP, UDP, ICMP, ICMPv6, ARP, IPv4, IPv6
│        parse_packet()          │  Extracts endpoints, lengths, safe payload previews
└───────────────┬────────────────┘
                │ Normalized Dict Record
       ┌────────┼────────────────────────┐
       ▼        ▼                        ▼
┌─────────────┐ ┌──────────────────────┐ ┌──────────────────────┐
│ display.py  │ │    statistics.py     │ │     exporter.py      │
│ PacketTable │ │   PacketStatistics   │ │ CsvExporter/JSON/PCAP│
│ Rich table  │ │ Protocol breakdown & │ │ Incremental exports  │
│ rendering   │ │ Top-talker IP counts │ │ (bounded memory)     │
└─────────────┘ └──────────────────────┘ └──────────────────────┘
```

### Module Responsibilities

| Module | Component | Description |
|---|---|---|
| `main.py` | CLI & Controller | CLI argument parsing via `argparse`, input validation, graceful `Ctrl+C` interrupt handling, and orchestration of capture and presentation. |
| `analyzer/capture.py` | `live_capture()`, `get_interfaces()` | Detects network adapters, auto-selects active defaults, and yields live packets one-by-one as a generator. Raises custom `CaptureError` on interface or privilege issues. |
| `analyzer/parser.py` | `parse_packet()` | Dissects TCP, UDP, ICMP, ICMPv6, ARP, IPv4, and IPv6 packets into structured metadata dictionaries. Builds safe, truncated hex and ASCII previews. |
| `analyzer/display.py` | `PacketTable` | Gathers parsed packets and formats them into an organized, color-coded terminal table using Rich. |
| `analyzer/statistics.py` | `PacketStatistics` | Tracks session metrics: total packets, byte volume, protocol distribution with visual progress bars, and top talkers (source & destination IPs). |
| `analyzer/exporter.py` | `CsvExporter`, `JsonExporter`, `PcapExporter` | Incrementally logs packet summaries to CSV/JSON or raw packets to PCAP, flushing each record immediately to prevent data loss upon interrupt. |

---

## 🖥️ Operating System Prerequisites

Live packet capture requires access to lower-level networking drivers:

### 1. Windows
- Install **[Npcap](https://npcap.com/#download)**.
- During installation, check **"Install Npcap in WinPcap API-compatible Mode"**.
- Run PowerShell or Command Prompt **as Administrator**.

### 2. Linux (Ubuntu/Debian/Fedora)
- Install `libpcap` and `tcpdump`:
  ```bash
  sudo apt-get update && sudo apt-get install -y libpcap-dev tcpdump
  ```
- Run the analyzer using `sudo` or grant packet capture capabilities to Python:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
  ```

### 3. macOS
- macOS includes `libpcap` by default.
- Run the analyzer with `sudo`:
  ```bash
  sudo python main.py -c 20
  ```

---

## 📦 Virtual Environment & Installation

```bash
# 1. Clone or navigate to the project directory
cd network-packet-analyzer

# 2. Create and activate a Python virtual environment
python -m venv venv

# Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# Linux / macOS:
source venv/bin/activate

# 3. Install pinned dependencies
pip install -r requirements.txt
```

`requirements.txt` specifies:
```text
scapy>=2.5,<3
rich>=13,<15
```

---

## 🚀 Usage Guide & CLI Options

```text
usage: network-packet-analyzer [-h] [-i INTERFACE] [--list-interfaces]
                               [-f BPF_FILTER] [-c COUNT] [--csv FILE]
                               [--payload-bytes PAYLOAD_BYTES] [--no-payload]

Passive Network Packet Analyzer - capture and analyze live network traffic.
```

### CLI Arguments

| Flag | Argument | Default | Description |
|---|---|---|---|
| `-i`, `--interface` | `STRING` | Auto-detect | Select network interface to capture on. |
| `--list-interfaces` | Flag | N/A | Print all detected interfaces and exit. |
| `-f`, `--filter` | `STRING` | None | BPF filter string (e.g., `"tcp"`, `"udp port 53"`). |
| `-c`, `--count` | `INT` | `0` (unlimited) | Number of packets to capture before stopping (`0` runs until `Ctrl+C`). Must be >= 0. |
| `--csv` | `PATH` | None | Filepath to write incremental CSV summaries. |
| `--payload-bytes` | `INT` | `32` | Max payload bytes to preview in hex and ASCII. Must be >= 0. |
| `--no-payload` | Flag | `False` | Omit payload preview entirely for privacy. |

---

## 💡 Practical Examples

### 1. List Available Interfaces
```bash
python main.py --list-interfaces
```

### 2. Capture on Default Interface (Auto-detected)
Captures 20 packets from the active interface:
```bash
python main.py -c 20
```

### 3. Capture on Specific Interface
```bash
# Windows
python main.py -i "Wi-Fi" -c 30

# Linux
sudo python main.py -i eth0 -c 30
```

### 4. Berkeley Packet Filters (BPF) Examples

- **Capture only HTTP/HTTPS web traffic:**
  ```bash
  python main.py -f "tcp port 80 or tcp port 443" -c 50
  ```
- **Inspect DNS lookups (UDP port 53):**
  ```bash
  python main.py -f "udp port 53" -c 10
  ```
- **Filter ICMP (Ping) packets:**
  ```bash
  python main.py -f "icmp" -c 10
  ```
- **Filter traffic between specific host:**
  ```bash
  python main.py -f "host 192.168.1.1 and tcp" -c 25
  ```

### 5. Incremental CSV Export
Export packet metadata as it arrives:
```bash
python main.py -c 50 --csv network_traffic.csv
```

### 6. Privacy Mode & Custom Payload Length
```bash
# Capture with payload extraction completely disabled
python main.py -c 30 --no-payload

# Capture with 64 bytes of payload preview
python main.py -c 30 --payload-bytes 64
```

---

## 🔍 Payload Preview Mechanism

Application-layer data (from Scapy's `Raw` layer) is extracted with safety and privacy in mind:
- **Hex View:** Bytes are represented as pairs of hexadecimal digits (`48 65 6c 6c 6f`).
- **Safe ASCII View:** Printable characters (`0x20` to `0x7E`) are displayed verbatim; non-printable or control characters are replaced with a period (`.`) to safeguard terminal integrity.
- **Truncation:** If the payload exceeds `--payload-bytes` (default: 32), an ellipsis `...` is appended.
- **Privacy Controls:** `--no-payload` suppresses payload dissection entirely.

*Example:*
```
47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a ... | GET / HTTP/1.1.. ...
```

---

## 📊 Session Output & Statistics

Upon completing the packet count or when gracefully stopping with `Ctrl+C`, the application renders:
1. **Packet Table:** Complete listing of all packets captured with timestamps, endpoints, protocols, lengths, and payload previews.
2. **Protocol Breakdown:** Tabular overview of protocol distributions with packet counts and percentage shares.
3. **Top Talkers:** Tables of top source and destination IP addresses.

*Example Output:*
```text
Captured Packets
┏━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ # ┃ Timestamp          ┃ Source             ┃ Destination        ┃ Protocol ┃ Length ┃ Payload Preview                        ┃
┡━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1 │ 2026-09-08 15:10:01│ 192.168.1.45:54231 │ 142.250.190.46:443 │ TCP      │    148 │ 16 03 03 00 59 ...  |  ....Y... ...    │
│ 2 │ 2026-09-08 15:10:02│ 192.168.1.45:51289 │ 1.1.1.1:53         │ UDP      │     72 │ a1 b2 01 00 00 ...  |  ....... ...     │
└───┴────────────────────┴────────────────────┴────────────────────┴──────────┴────────┴────────────────────────────────────────┘

━━━ Capture Statistics ━━━
  Total packets captured: 2
  Total bytes captured:   220

Protocol Breakdown
┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Protocol ┃ Packets ┃ Percentage ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━┩
│ TCP      │       1 │      50.0% │
│ UDP      │       1 │      50.0% │
└──────────┴─────────┴────────────┘
```

---

## 📁 Export Formats & Field Consistency

The analyzer supports 3 incremental export formats (flushed immediately per record, safe against interrupt):

### 1. CSV Export Schema (`--csv exports/capture.csv`)
Consistent field naming across code, CLI, and exports:

| Field | Type | Description | Example |
|---|---|---|---|
| `timestamp` | String | Packet capture time (millisecond precision) | `2026-09-08 15:30:10.273` |
| `src_ip` | String | Source IP address (IPv4 / IPv6 / MAC fallback) | `172.25.68.68` |
| `dst_ip` | String | Destination IP address (IPv4 / IPv6 / MAC fallback) | `172.217.114.4` |
| `src_port` | String | Source port number (or `-` for non-port protocols) | `55654` |
| `dst_port` | String | Destination port number (or `-` for non-port protocols) | `443` |
| `protocol` | String | Dissected protocol (`TCP`, `UDP`, `ICMP`, `ICMPv6`, `ARP`, etc.) | `TCP` |
| `length` | Integer | Total wire packet length in bytes | `1466` |
| `payload_hex` | String | Safe truncated hexadecimal payload preview | `17 03 03 40 11 ...` |
| `payload_ascii` | String | Safe ASCII preview (non-printable replaced with `.`) | `...@...\|#....e~\...` |

### 2. JSON Array Export (`--json exports/capture.json`)
Exports structured JSON array records with the exact same normalized keys for automated parsing or ingestion into log management pipelines.

### 3. PCAP Raw Dump (`--pcap exports/session.pcap`)
Incrementally writes unparsed, raw captured frames in standard libpcap format for external deep forensics in Wireshark or `tcpdump`. Default is OFF for privacy and disk conservation.

---

## 🛠️ Safe Testing & Validation Recipes

To safely test the analyzer on your local machine without exposing sensitive external traffic:

1. **Local HTTP Server (TCP):**
   ```bash
   # Terminal 1:
   python -m http.server 8080

   # Terminal 2 (Monitor):
   python main.py -f "tcp port 8080" -c 10

   # Terminal 3 (Generate Traffic):
   curl http://localhost:8080
   ```

2. **DNS Query (UDP):**
   ```bash
   # Monitor:
   python main.py -f "udp port 53" -c 5

   # Generate (in another shell):
   nslookup example.com
   ```

3. **ICMP Echo (Ping):**
   ```bash
   # Monitor:
   python main.py -f "icmp" -c 4

   # Generate:
   ping 127.0.0.1
   ```

---

## ⚡ Troubleshooting & Permission Issues

- **`CaptureError: Permission denied: packet capture requires elevated privileges`**
  - **Windows:** Right-click terminal and choose **Run as Administrator**.
  - **Linux / macOS:** Run with `sudo python main.py ...`.
- **`CaptureError: Scapy is not installed`**
  - Activate your virtual environment and run `pip install -r requirements.txt`.
- **`CaptureError: Interface '<name>' not found`**
  - Run `python main.py --list-interfaces` to see the exact OS-level device names.
- **Windows Npcap issues:**
  - Verify that the Npcap service is running (`net start npcap` in an administrative shell).

---

## 🔬 Architectural Decisions: Why Scapy over Raw Sockets?

| Criteria | Raw Sockets (`socket.AF_INET, SOCK_RAW`) | Scapy Engine (`AsyncSniffer`) |
|---|---|---|
| **Portability** | Highly OS-dependent; Windows strictly restricts raw socket usage for non-admin TCP/UDP capture. | Unified API across Windows (Npcap), Linux (libpcap), and macOS. |
| **Layer 2 Visibility** | Inability to inspect Ethernet / ARP frames directly on many socket types. | Direct access to Layer 2 Ethernet, ARP, 802.1Q VLAN headers, and beyond. |
| **BPF Filtering** | Requires custom userland filter logic or complex platform-specific socket filters. | BPF filtering is delegated to the libpcap/Npcap capture backend, reducing packets delivered to the application when supported by the capture stack. |
| **Dissection Support** | Requires manual struct unpacking for every protocol header and option. | Native decoding of 500+ network protocols and layer abstractions (IPv4/IPv6, TCP, UDP, ICMP, ICMPv6, ARP). |

---

## ⚠️ Known Limitations

1. **Encrypted Payloads (TLS/SSL):** Transport layer packets over HTTPS (443), SSH (22), or SFTP encrypt application data. The payload preview displays encrypted ciphertext bytes rather than plaintext.
2. **Promiscuous & Monitor Mode:** Capturing packets for adjacent nodes on a switched network requires network tap/port mirroring (SPAN) configuration. Wireless monitor mode requires supported hardware and driver configurations.
3. **Virtual Adapters & Loopback:** On Windows, localhost loopback captures require Npcap's loopback adapter to be enabled during installation.

---

## 🎓 Internship & Interview Talking Points

- **Producer-Consumer / Generator Pipeline:** `live_capture()` acts as a memory-efficient generator yielding packet objects on demand rather than loading full captures into RAM (`store=False` prevents Scapy from retaining the complete capture in an internal packet list, keeping memory usage bounded by the application pipeline).
- **Separation of Concerns:** Capture, parsing, terminal formatting, statistical accumulation, and file exports are completely decoupled. Modules can be tested or swapped independently.
- **Defensive & Passive Posture:** The code does not craft (`IP()/TCP()`), transmit (`send()`), or inject (`sr()`) packets. It solely listens via passive sniff interfaces.
- **Robust Exception Design:** Clean custom exceptions (`CaptureError`) catch system failures and present actionable remediation advice instead of raw tracebacks.
