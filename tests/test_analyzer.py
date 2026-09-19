"""Comprehensive unit tests for the Network Packet Analyzer modules."""

import csv
import os
import tempfile
import unittest

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from analyzer.capture import (
    CaptureError,
    get_default_interface,
    get_interfaces,
    validate_interface,
)
from analyzer.display import PacketTable
from analyzer.exporter import CSV_FIELDS, CsvExporter, JsonExporter, PcapExporter
from analyzer.parser import _safe_ascii, parse_packet, sanitize_payload, sanitize_text
from analyzer.statistics import PacketStatistics


class TestParser(unittest.TestCase):
    """Test packet parsing, normalization, and payload preview."""

    def test_safe_ascii(self):
        """Ensure safe ASCII replaces control characters and non-printables with '.'"""
        data = b"Hello\x00\x01\x02 World!\x7f\x80\xff"
        safe = _safe_ascii(data)
        self.assertEqual(safe, "Hello... World!...")

    def test_parse_tcp_packet(self):
        """Parse IPv4 + TCP packet with payload."""
        packet = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"GET /index.html HTTP/1.1\r\n")
        record = parse_packet(packet, payload_bytes=16, no_payload=False)

        self.assertEqual(record["src_ip"], "192.168.1.50")
        self.assertEqual(record["dst_ip"], "10.0.0.1")
        self.assertEqual(record["src_port"], "12345")
        self.assertEqual(record["dst_port"], "80")
        self.assertEqual(record["protocol"], "TCP")
        self.assertGreater(record["length"], 0)
        self.assertTrue("47 45 54" in record["payload_hex"])  # 'GET'
        self.assertTrue("GET" in record["payload_ascii"])

    def test_parse_udp_packet(self):
        """Parse IPv4 + UDP packet."""
        packet = IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=5353, dport=53) / Raw(load=b"\x00\x01test")
        record = parse_packet(packet)

        self.assertEqual(record["src_ip"], "192.168.1.100")
        self.assertEqual(record["dst_ip"], "8.8.8.8")
        self.assertEqual(record["src_port"], "5353")
        self.assertEqual(record["dst_port"], "53")
        self.assertEqual(record["protocol"], "UDP")

    def test_parse_icmp_packet(self):
        """Parse ICMP packet."""
        packet = IP(src="192.168.1.1", dst="192.168.1.2") / ICMP(type=8, code=0)
        record = parse_packet(packet)

        self.assertEqual(record["src_ip"], "192.168.1.1")
        self.assertEqual(record["dst_ip"], "192.168.1.2")
        self.assertEqual(record["protocol"], "ICMP")
        self.assertEqual(record["src_port"], "-")
        self.assertEqual(record["dst_port"], "-")

    def test_parse_arp_packet(self):
        """Parse ARP packet."""
        packet = ARP(psrc="192.168.1.1", pdst="192.168.1.254", hwsrc="aa:bb:cc:dd:ee:ff")
        record = parse_packet(packet)

        self.assertEqual(record["src_ip"], "192.168.1.1")
        self.assertEqual(record["dst_ip"], "192.168.1.254")
        self.assertEqual(record["protocol"], "ARP")

    def test_parse_ipv6_packet(self):
        """Parse IPv6 packet."""
        packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=443, dport=54321)
        record = parse_packet(packet)

        self.assertEqual(record["src_ip"], "2001:db8::1")
        self.assertEqual(record["dst_ip"], "2001:db8::2")
        self.assertEqual(record["protocol"], "TCP")
        self.assertEqual(record["src_port"], "443")
        self.assertEqual(record["dst_port"], "54321")

    def test_no_payload_option(self):
        """Verify --no-payload strips all payload preview data."""
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=1234) / Raw(load=b"SensitivePassword123")
        record = parse_packet(packet, no_payload=True)

        self.assertEqual(record["payload_hex"], "")
        self.assertEqual(record["payload_ascii"], "")

    def test_payload_truncation(self):
        """Verify payload is properly truncated when exceeding max_bytes."""
        long_data = b"A" * 100
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1000, dport=2000) / Raw(load=long_data)
        record = parse_packet(packet, payload_bytes=10)

        self.assertTrue(record["payload_hex"].endswith("..."))
        self.assertTrue(record["payload_ascii"].endswith("..."))
        # Only 10 bytes rendered
        hex_bytes = record["payload_hex"].replace(" ...", "").split()
        self.assertEqual(len(hex_bytes), 10)

    def test_2fa_manual_secret_key_masking(self):
        """Verify 2FA manual secret key (Base32 16/32 char) is automatically redacted in hex and ASCII."""
        # 16-character Base32 TOTP key
        packet = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=1234, dport=80) / Raw(load=b"Key: JBSWY3DPEHPK3PXP")
        record = parse_packet(packet, payload_bytes=32)

        self.assertNotIn("JBSWY3DPEHPK3PXP", record["payload_ascii"])
        self.assertIn("****************", record["payload_ascii"])
        # In hex, '*' is 0x2a, verify original hex characters are not exposed
        self.assertIn("2a 2a 2a", record["payload_hex"])

    def test_otpauth_secret_masking(self):
        """Verify otpauth:// URI secret query parameters are masked."""
        raw = b"otpauth://totp/GitHub:user?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=GitHub"
        packet = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=1234, dport=80) / Raw(load=raw)
        record = parse_packet(packet, payload_bytes=80)

        self.assertNotIn("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", record["payload_ascii"])
        self.assertIn("secret=***", record["payload_ascii"])

    def test_auth_header_masking(self):
        """Verify HTTP Authorization Bearer token is masked."""
        raw = b"Authorization: Bearer my_secret_token_12345\r\n"
        packet = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=1234, dport=80) / Raw(load=raw)
        record = parse_packet(packet, payload_bytes=50)

        self.assertNotIn("my_secret_token_12345", record["payload_ascii"])
        self.assertIn("Authorization: Bearer ***", record["payload_ascii"])

    def test_disable_secret_masking(self):
        """Verify sanitize_credentials=False retains raw payload when explicitly disabled."""
        raw = b"Key: JBSWY3DPEHPK3PXP"
        packet = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=1234, dport=80) / Raw(load=raw)
        record = parse_packet(packet, payload_bytes=32, sanitize_credentials=False)

        self.assertIn("JBSWY3DPEHPK3PXP", record["payload_ascii"])

    def test_sanitize_text_utility(self):
        """Verify standalone string sanitization for dashboard views."""
        text = "2FA setup manual code: ABCD EFGH IJKL MNOP"
        sanitized = sanitize_text(text)
        self.assertNotIn("ABCD EFGH IJKL MNOP", sanitized)
        self.assertIn("*******************", sanitized)


class TestStatistics(unittest.TestCase):
    """Test packet statistics accumulation and metrics calculation."""

    def setUp(self):
        self.stats = PacketStatistics()

    def test_empty_statistics(self):
        self.assertEqual(self.stats.total_packets, 0)
        self.assertEqual(self.stats.total_bytes, 0)
        # render should not crash on 0 packets
        self.stats.render()

    def test_packet_accumulation(self):
        r1 = {"protocol": "TCP", "length": 100, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
        r2 = {"protocol": "TCP", "length": 200, "src_ip": "1.1.1.1", "dst_ip": "3.3.3.3"}
        r3 = {"protocol": "UDP", "length": 50, "src_ip": "4.4.4.4", "dst_ip": "2.2.2.2"}

        self.stats.update(r1)
        self.stats.update(r2)
        self.stats.update(r3)

        self.assertEqual(self.stats.total_packets, 3)
        self.assertEqual(self.stats.total_bytes, 350)
        self.assertEqual(self.stats.protocol_counts["TCP"], 2)
        self.assertEqual(self.stats.protocol_counts["UDP"], 1)
        self.assertEqual(self.stats.source_ips["1.1.1.1"], 2)
        self.assertEqual(self.stats.destination_ips["2.2.2.2"], 2)

        # render should format without error
        self.stats.render()


class TestExporter(unittest.TestCase):
    """Test incremental CSV export."""

    def test_csv_export_incremental(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            with CsvExporter(tmp_path) as exporter:
                record = {
                    "timestamp": "2026-09-08 12:00:00.000",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "src_port": "8080",
                    "dst_port": "443",
                    "protocol": "TCP",
                    "length": 128,
                    "payload_hex": "aa bb cc",
                    "payload_ascii": "...",
                }
                exporter.write_record(record)
                self.assertEqual(exporter.row_count, 1)

            # Read back CSV
            with open(tmp_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["src_ip"], "10.0.0.1")
            self.assertEqual(rows[0]["dst_port"], "443")
            self.assertEqual(rows[0]["protocol"], "TCP")
            self.assertEqual(list(rows[0].keys()), CSV_FIELDS)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_json_export_incremental(self):
        import json
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            with JsonExporter(tmp_path) as exporter:
                record = {
                    "timestamp": "2026-09-08 12:00:00.000",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "src_port": "8080",
                    "dst_port": "443",
                    "protocol": "TCP",
                    "length": 128,
                    "payload_hex": "aa bb cc",
                    "payload_ascii": "...",
                }
                exporter.write_record(record)
                self.assertEqual(exporter.row_count, 1)

            with open(tmp_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["src_ip"], "10.0.0.1")
            self.assertEqual(data[0]["protocol"], "TCP")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_pcap_export(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            with PcapExporter(tmp_path) as exporter:
                pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=100, dport=200)
                exporter.write_packet(pkt)
                self.assertEqual(exporter.row_count, 1)

            self.assertGreater(os.path.getsize(tmp_path), 0)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestDisplay(unittest.TestCase):
    """Test PacketTable rendering and formatting."""

    def test_packet_table(self):
        table = PacketTable()
        self.assertEqual(table.count, 0)
        # Empty render shouldn't crash
        table.render()

        record = {
            "timestamp": "2026-09-08 12:00:00.000",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "src_port": "54321",
            "dst_port": "53",
            "protocol": "UDP",
            "length": 64,
            "payload_hex": "12 34",
            "payload_ascii": "..",
        }
        table.add_packet(record)
        self.assertEqual(table.count, 1)
        table.render()


class TestCaptureInterfaces(unittest.TestCase):
    """Test interface lookup and validation."""

    def test_get_interfaces(self):
        ifaces = get_interfaces()
        self.assertIsInstance(ifaces, list)

    def test_get_default_interface(self):
        iface = get_default_interface()
        self.assertIsInstance(iface, str)
        self.assertGreater(len(iface), 0)

    def test_validate_invalid_interface(self):
        with self.assertRaises(CaptureError):
            validate_interface("non_existent_adapter_xyz_999")


if __name__ == "__main__":
    unittest.main()
