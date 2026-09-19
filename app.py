"""Streamlit Web Dashboard for Network Packet Analyzer.

Enables interactive localhost inspection of live or exported network traffic,
protocol analytics, top-talker visual charts, and detailed payload inspection.

Run with:
    streamlit run app.py
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Import analyzer core components
from analyzer.capture import (
    CaptureError,
    get_default_interface,
    get_interface_details,
    live_capture,
)
from analyzer.exporter import CSV_FIELDS
from analyzer.parser import parse_packet
from analyzer.statistics import PacketStatistics

# Page configuration
st.set_page_config(
    page_title="Network Packet Analyzer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E88E5;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #757575;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 16px;
        border-left: 5px solid #1E88E5;
    }
    .badge {
        display: inline-block;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 600;
        margin-right: 6px;
    }
    .badge-passive { background-color: #E8F5E9; color: #2E7D32; }
    .badge-live { background-color: #E3F2FD; color: #1565C0; }
    </style>
    """,
    unsafe_allow_html=True,
)

# Header
st.markdown('<div class="main-header">🔍 Network Packet Analyzer</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">'
    '<span class="badge badge-passive">100% PASSIVE</span>'
    '<span class="badge badge-live">DEFENSIVE VISIBILITY</span> '
    'Real-time packet capture, protocol dissection, top talkers & payload inspection on <code>localhost</code>'
    '</div>',
    unsafe_allow_html=True,
)

# Sidebar
st.sidebar.title("⚙️ Capture Settings")

mode = st.sidebar.radio(
    "Choose Data Source:",
    ["Inspect Existing Capture", "Live Packet Capture", "Load Sample Demo Data"],
    index=0,
)

packets_data = []

# --- MODE 1: INSPECT EXISTING FILE ---
if mode == "Inspect Existing Capture":
    st.sidebar.subheader("📂 Select Capture File")
    exports_dir = Path("exports")
    available_files = []
    if exports_dir.exists():
        available_files = [f.name for f in exports_dir.glob("*.csv")] + [f.name for f in exports_dir.glob("*.json")]

    uploaded_file = st.sidebar.file_uploader("Upload CSV or JSON capture:", type=["csv", "json"])

    if uploaded_file is not None:
        try:
            if uploaded_file.name.endswith(".csv"):
                df_raw = pd.read_csv(uploaded_file)
                packets_data = df_raw.to_dict(orient="records")
            else:
                packets_data = json.load(uploaded_file)
            st.sidebar.success(f"Loaded {len(packets_data)} packets from uploaded file")
        except Exception as e:
            st.sidebar.error(f"Error loading uploaded file: {e}")

    elif available_files:
        selected_file = st.sidebar.selectbox("Or choose from exports/:", available_files)
        file_path = exports_dir / selected_file
        try:
            if selected_file.endswith(".csv"):
                df_raw = pd.read_csv(file_path)
                packets_data = df_raw.to_dict(orient="records")
            else:
                with open(file_path, "r", encoding="utf-8") as f:
                    packets_data = json.load(f)
            st.sidebar.info(f"Loaded {len(packets_data)} packets from {selected_file}")
        except Exception as e:
            st.sidebar.error(f"Error reading file: {e}")
    else:
        st.sidebar.warning("No existing export found in exports/. Run a capture or upload a file.")

# --- MODE 2: LIVE PACKET CAPTURE ---
elif mode == "Live Packet Capture":
    st.sidebar.subheader("🌐 Network Adapter")
    try:
        ifaces = get_interface_details()
        iface_options = {
            f"{item['index']}: {item['name']} ({item['ip']})": item["device"]
            for item in ifaces
        }
        selected_label = st.sidebar.selectbox("Select Interface:", list(iface_options.keys()))
        selected_device = iface_options[selected_label]
    except Exception as e:
        selected_device = None
        st.sidebar.error(f"Could not enumerate interfaces: {e}")

    bpf_filter = st.sidebar.text_input("BPF Filter (optional):", value="", placeholder="e.g. tcp, udp port 53, icmp")
    packet_count = st.sidebar.slider("Packets to Capture:", min_value=5, max_value=200, value=20, step=5)
    payload_preview_bytes = st.sidebar.number_input("Payload Preview Bytes:", min_value=0, max_value=128, value=32)
    no_payload = st.sidebar.checkbox("Privacy Mode (--no-payload)", value=False)

    start_capture = st.sidebar.button("▶️ Start Live Capture", type="primary")

    if start_capture and selected_device:
        progress_bar = st.progress(0)
        status_text = st.empty()
        status_text.info(f"Capturing {packet_count} packets on interface...")

        captured_records = []
        try:
            for raw_packet in live_capture(
                interface=selected_device,
                bpf_filter=bpf_filter.strip() if bpf_filter.strip() else None,
                count=packet_count,
            ):
                rec = parse_packet(
                    raw_packet,
                    payload_bytes=payload_preview_bytes,
                    no_payload=no_payload,
                )
                captured_records.append(rec)
                progress_bar.progress(len(captured_records) / packet_count)
                status_text.text(f"Captured {len(captured_records)}/{packet_count}: {rec['protocol']} {rec['src_ip']} -> {rec['dst_ip']}")

            status_text.success(f"✓ Capture complete: {len(captured_records)} packets captured!")
            packets_data = captured_records

            # Save to session state so it persists on rerun
            st.session_state["live_data"] = packets_data

        except CaptureError as exc:
            status_text.error(f"Capture Error: {exc}")
        except Exception as exc:
            status_text.error(f"Unexpected Error: {exc}")

    elif "live_data" in st.session_state and st.session_state["live_data"]:
        packets_data = st.session_state["live_data"]

# --- MODE 3: SAMPLE DEMO DATA ---
else:
    st.sidebar.info("Generating synthetic multi-protocol packets (TCP, UDP, ICMP, ICMPv6, ARP) without requiring root/admin privileges.")
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw

    ether = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    demo_pkts = [
        ether / IP(src="192.168.1.105", dst="142.250.190.46") / TCP(sport=54231, dport=443) / Raw(b"\x17\x03\x03\x00\x2fTLS_Application_Data_Encrypted"),
        ether / IP(src="142.250.190.46", dst="192.168.1.105") / TCP(sport=443, dport=54231) / Raw(b"\x17\x03\x03\x01\x75Server_Hello_Response"),
        ether / IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=51289, dport=53) / Raw(b"\x12\x34\x01\x00\x00\x01\x00\x00google.com"),
        ether / IP(src="8.8.8.8", dst="192.168.1.105") / UDP(sport=53, dport=51289) / Raw(b"\x12\x34\x81\x80\x00\x01\x00\x01google.com"),
        ether / IP(src="192.168.1.105", dst="192.168.1.1") / ICMP(type=8, code=0) / Raw(b"Ping_Echo_Request_Sample"),
        ether / IP(src="192.168.1.1", dst="192.168.1.105") / ICMP(type=0, code=0) / Raw(b"Ping_Echo_Reply_Sample"),
        ether / ARP(op=1, psrc="192.168.1.105", pdst="192.168.1.1"),
        ether / ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.105"),
        ether / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest() / Raw(b"ICMPv6_Ping_Test"),
        ether / IP(src="192.168.1.105", dst="93.184.216.34") / TCP(sport=58912, dport=80) / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ]
    packets_data = [parse_packet(p, payload_bytes=32) for p in demo_pkts]


# --- RENDER DASHBOARD IF DATA EXISTS ---
if packets_data:
    df = pd.DataFrame(packets_data)

    # Ensure all expected columns exist
    for col in CSV_FIELDS:
        if col not in df.columns:
            df[col] = "-"

    # Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    total_pkts = len(df)
    total_bytes = int(df["length"].sum()) if "length" in df.columns else 0
    unique_src = df["src_ip"].nunique()
    top_proto = df["protocol"].value_counts().index[0] if not df.empty else "N/A"
    top_proto_pct = (df["protocol"].value_counts().iloc[0] / total_pkts * 100) if total_pkts > 0 else 0

    m1.metric("📦 Total Packets", f"{total_pkts:,}")
    m2.metric("💾 Total Volume", f"{total_bytes:,} bytes")
    m3.metric("🌐 Unique Endpoints", f"{unique_src}")
    m4.metric("📊 Dominant Protocol", f"{top_proto} ({top_proto_pct:.1f}%)")

    st.markdown("---")

    # Visualizations Row
    c1, c2 = st.columns([1, 1])

    with c1:
        st.subheader("📊 Protocol Distribution")
        proto_counts = df["protocol"].value_counts().reset_index()
        proto_counts.columns = ["Protocol", "Packets"]
        fig_pie = px.pie(
            proto_counts,
            names="Protocol",
            values="Packets",
            hole=0.45,
            color_discrete_sequence=px.colors.qualitative.Pastel,
        )
        fig_pie.update_layout(margin=dict(t=20, b=20, l=20, r=20), height=300)
        st.plotly_chart(fig_pie, use_container_width=True)

    with c2:
        st.subheader("🎯 Top Talkers (Source IPs)")
        src_counts = df[df["src_ip"] != "-"]["src_ip"].value_counts().head(7).reset_index()
        src_counts.columns = ["Source IP", "Packets"]
        fig_bar = px.bar(
            src_counts,
            x="Packets",
            y="Source IP",
            orientation="h",
            color="Packets",
            color_continuous_scale="Blues",
        )
        fig_bar.update_layout(margin=dict(t=20, b=20, l=20, r=20), height=300, yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig_bar, use_container_width=True)

    # Interactive Packet Explorer Table
    st.subheader("📋 Packet Stream Explorer")

    col_filter1, col_filter2 = st.columns([1, 2])
    with col_filter1:
        available_protos = ["All"] + sorted(list(df["protocol"].unique()))
        selected_proto = st.selectbox("Filter by Protocol:", available_protos)
    with col_filter2:
        search_query = st.text_input("🔍 Search by IP, Port or Keyword:", placeholder="e.g. 192.168, 443, DNS, GET")

    filtered_df = df.copy()
    if selected_proto != "All":
        filtered_df = filtered_df[filtered_df["protocol"] == selected_proto]
    if search_query.strip():
        q = search_query.strip().lower()
        filtered_df = filtered_df[
            filtered_df["src_ip"].astype(str).str.lower().str.contains(q)
            | filtered_df["dst_ip"].astype(str).str.lower().str.contains(q)
            | filtered_df["src_port"].astype(str).str.lower().str.contains(q)
            | filtered_df["dst_port"].astype(str).str.lower().str.contains(q)
            | filtered_df["payload_ascii"].astype(str).str.lower().str.contains(q)
        ]

    st.dataframe(
        filtered_df[["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "payload_hex", "payload_ascii"]],
        use_container_width=True,
        hide_index=True,
    )

    # Detailed Packet Inspection Row
    st.markdown("---")
    st.subheader("🔬 Deep Payload Inspector")
    selected_idx = st.selectbox("Select Packet Row # to Inspect:", range(1, len(filtered_df) + 1), format_func=lambda x: f"Packet #{x} - {filtered_df.iloc[x-1]['protocol']} ({filtered_df.iloc[x-1]['src_ip']} -> {filtered_df.iloc[x-1]['dst_ip']})")

    if selected_idx is not None and not filtered_df.empty:
        pkt = filtered_df.iloc[selected_idx - 1]
        p_col1, p_col2 = st.columns(2)

        with p_col1:
            st.markdown("**Header Metadata:**")
            st.code(
                f"Timestamp:   {pkt['timestamp']}\n"
                f"Protocol:    {pkt['protocol']}\n"
                f"Source:      {pkt['src_ip']}:{pkt['src_port']}\n"
                f"Destination: {pkt['dst_ip']}:{pkt['dst_port']}\n"
                f"Wire Length: {pkt['length']} bytes",
                language="text",
            )

        with p_col2:
            st.markdown("**Hex & ASCII Preview:**")
            st.code(
                f"HEX:   {pkt['payload_hex'] or '(no application payload)'}\n\n"
                f"ASCII: {pkt['payload_ascii'] or '(no application payload)'}",
                language="text",
            )

    # Download Buttons
    st.markdown("---")
    d1, d2 = st.columns(2)
    with d1:
        csv_bytes = filtered_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="⬇️ Download Filtered Data as CSV",
            data=csv_bytes,
            file_name="packet_analysis_export.csv",
            mime="text/csv",
        )
    with d2:
        json_bytes = json.dumps(filtered_df.to_dict(orient="records"), indent=2).encode("utf-8")
        st.download_button(
            label="⬇️ Download Filtered Data as JSON",
            data=json_bytes,
            file_name="packet_analysis_export.json",
            mime="application/json",
        )

else:
    st.info("👈 Use the sidebar to start a live packet capture or inspect a saved file from exports/.")
