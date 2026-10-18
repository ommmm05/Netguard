"""
PCAP parsing helpers — streaming packet parsing for PCAP uploads and PCAP file ingestion.
"""

from __future__ import annotations

import base64
import os
import tempfile
from collections import defaultdict

import plotly.graph_objects as go
from scapy.all import IP, TCP, UDP, ICMP, ARP
from scapy.utils import PcapReader

from capture.decoder import process_packet
from capture.pcap_ingest import ingest_pcap_file, ingest_packet_iterator, iter_packets
from visibility.device_classifier import classify_device
from visibility.ingest_state import IngestSnapshot
from visibility.network_utils import (
    PROTO_MAP,
    detect_protocol_from_ports,
    is_displayable_ip,
    protocol_label,
)

PROTO_LOOKUP = {
    80: "HTTP", 443: "HTTPS", 502: "Modbus",
    20000: "DNP3", 102: "S7comm", 44818: "EtherNet/IP",
    22: "SSH", 23: "Telnet", 53: "DNS", 161: "SNMP"
}


def detect_protocol(pkt) -> str:
    """Protocol detection logic by layer and destination/source port."""
    if pkt.haslayer("TCP"):
        dport = int(pkt["TCP"].dport)
        sport = int(pkt["TCP"].sport)
        return PROTO_LOOKUP.get(dport) or PROTO_LOOKUP.get(sport) or "TCP"
    if pkt.haslayer("UDP"):
        dport = int(pkt["UDP"].dport)
        sport = int(pkt["UDP"].sport)
        return PROTO_LOOKUP.get(dport) or PROTO_LOOKUP.get(sport) or "UDP"
    if pkt.haslayer("ICMP"):
        return "ICMP"
    if pkt.haslayer("ARP"):
        return "ARP"
    return "Other"


def parse_pcap_contents(contents: str, filename: str) -> dict:
    """
    Decodes a base64 encoded PCAP upload string, writes to temp file, and parses live packet flows.
    Returns Cytoscape elements, flow table data, asset table data, protocol breakdown figure, and summary metrics.
    """
    if not contents or "," not in contents:
        return {
            "elements": [],
            "flows": [],
            "assets": [],
            "total_packets": "0",
            "unique_ips": "0",
            "protocols_count": "0",
            "top_talker": "None",
            "proto_figure": go.Figure(),
        }

    header, content_string = contents.split(",", 1)
    decoded = base64.b64decode(content_string)

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(decoded)
            temp_path = tmp.name

        flows: dict[tuple[str, str, str], dict] = {}
        ip_stats: dict[str, dict] = defaultdict(lambda: {"packets": 0, "bytes": 0, "mac": "—", "ports": set()})
        proto_counts: dict[str, int] = defaultdict(int)

        reader = PcapReader(temp_path)
        total_packets = 0

        try:
            for pkt in reader:
                total_packets += 1
                pkt_len = len(bytes(pkt))
                pkt_time = float(getattr(pkt, "time", 0) or 0)

                src_ip, dst_ip = None, None
                src_mac = "—"
                dport = 0

                if pkt.haslayer(IP):
                    src_ip = str(pkt[IP].src)
                    dst_ip = str(pkt[IP].dst)
                elif pkt.haslayer(ARP):
                    src_ip = str(getattr(pkt[ARP], "psrc", ""))
                    dst_ip = str(getattr(pkt[ARP], "pdst", ""))
                    src_mac = str(getattr(pkt[ARP], "hwsrc", "—"))

                if not src_ip or not dst_ip:
                    continue

                if not is_displayable_ip(src_ip) and not is_displayable_ip(dst_ip):
                    continue

                proto = detect_protocol(pkt)
                proto_counts[proto] += 1

                if pkt.haslayer(TCP):
                    dport = int(pkt[TCP].dport)
                elif pkt.haslayer(UDP):
                    dport = int(pkt[UDP].dport)

                if is_displayable_ip(src_ip):
                    ip_stats[src_ip]["packets"] += 1
                    ip_stats[src_ip]["bytes"] += pkt_len
                    if src_mac != "—":
                        ip_stats[src_ip]["mac"] = src_mac

                if is_displayable_ip(dst_ip):
                    ip_stats[dst_ip]["packets"] += 1
                    ip_stats[dst_ip]["bytes"] += pkt_len
                    if dport > 0:
                        ip_stats[dst_ip]["ports"].add(dport)

                key = (src_ip, dst_ip, proto)
                if key not in flows:
                    flows[key] = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": proto,
                        "packets": 0,
                        "bytes": 0,
                        "first_seen": pkt_time,
                        "last_seen": pkt_time,
                    }

                fl = flows[key]
                fl["packets"] += 1
                fl["bytes"] += pkt_len
                if pkt_time < fl["first_seen"] or fl["first_seen"] == 0:
                    fl["first_seen"] = pkt_time
                if pkt_time > fl["last_seen"]:
                    fl["last_seen"] = pkt_time

        finally:
            try:
                reader.close()
            except Exception:
                pass

        # Build Cytoscape elements
        elements = []
        node_ids = set()

        for ip in ip_stats:
            if not is_displayable_ip(ip):
                continue

            ports_list = [{"port": p, "service": PROTO_LOOKUP.get(p, "")} for p in ip_stats[ip]["ports"]]
            dtype = classify_device({"ip": ip, "ports": ports_list, "mac": ip_stats[ip]["mac"]})

            elements.append({
                "data": {
                    "id": ip,
                    "label": f"{ip}\n{dtype}",
                    "device_type": dtype,
                    "mac": ip_stats[ip]["mac"],
                    "ports": [p["port"] for p in ports_list],
                }
            })
            node_ids.add(ip)

        for (src, dst, proto), fl in flows.items():
            if is_displayable_ip(src) and is_displayable_ip(dst):
                elements.append({
                    "data": {
                        "id": f"{src}-{dst}-{proto}",
                        "source": src,
                        "target": dst,
                        "protocol": proto,
                        "packets": fl["packets"],
                        "bytes": fl["bytes"],
                    }
                })

        # Flow table data
        flow_table = []
        for fl in flows.values():
            duration = max(0.0, round(fl["last_seen"] - fl["first_seen"], 2)) if fl["first_seen"] > 0 else 0.0
            flow_table.append({
                "src_ip": fl["src_ip"],
                "dst_ip": fl["dst_ip"],
                "protocol": fl["protocol"],
                "packets": fl["packets"],
                "bytes": fl["bytes"],
                "duration_s": duration,
            })

        # Asset table data
        asset_table = []
        for ip, st in ip_stats.items():
            ports_str = ", ".join(str(p) for p in sorted(st["ports"])[:5]) or "None"
            ports_list = [{"port": p, "service": PROTO_LOOKUP.get(p, "")} for p in st["ports"]]
            dtype = classify_device({"ip": ip, "ports": ports_list, "mac": st["mac"]})
            asset_table.append({
                "ip": ip,
                "mac": st["mac"],
                "type": dtype,
                "ports": ports_str,
            })

        # Metrics
        unique_ips = len(ip_stats)
        top_talker = "None"
        if ip_stats:
            top_talker = max(ip_stats, key=lambda k: ip_stats[k]["packets"])

        # Protocol Chart
        if proto_counts:
            labels = list(proto_counts.keys())
            values = list(proto_counts.values())
            fig = go.Figure(go.Bar(x=values, y=labels, orientation="h", marker_color="#378ADD"))
            fig.update_layout(
                margin=dict(l=0, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(size=11),
                height=180,
            )
        else:
            fig = go.Figure()

        return {
            "elements": elements,
            "flows": flow_table,
            "assets": asset_table,
            "total_packets": f"{total_packets:,}",
            "unique_ips": str(unique_ips),
            "protocols_count": str(len(proto_counts)),
            "top_talker": top_talker,
            "proto_figure": fig,
        }

    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


__all__ = [
    "PROTO_MAP",
    "PROTO_LOOKUP",
    "detect_protocol",
    "detect_protocol_from_ports",
    "protocol_label",
    "iter_packets",
    "ingest_pcap_file",
    "ingest_packet_iterator",
    "parse_pcap_contents",
]
