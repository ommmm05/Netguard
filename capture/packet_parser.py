"""
capture/packet_parser.py — Dedicated TShark packet parsing layer.

Normalizes streaming TShark JSON/EK frames into structured, null-safe `ParsedPacket`
telemetry objects with strict payload privacy controls.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from config import MAX_PAYLOAD_BYTES

logger = logging.getLogger(__name__)


@dataclass
class ParsedPacket:
    frame_number: int = 0
    timestamp: float = field(default_factory=time.time)
    src_mac: str = "00:00:00:00:00:00"
    dst_mac: str = "00:00:00:00:00:00"
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    transport_protocol: str = "OTHER"
    network_protocol: str = "IP"
    packet_length: int = 0
    tcp_flags: dict[str, bool] = field(default_factory=dict)
    ttl: int = 64
    payload_preview: str = ""
    protocol_info: str = ""
    http_meta: Optional[dict[str, Any]] = None
    dns_meta: Optional[dict[str, Any]] = None
    tls_meta: Optional[dict[str, Any]] = None
    icmp_meta: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        """Serializable dictionary representation for APIs/SSE."""
        return {
            "frameNumber": self.frame_number,
            "timestamp": self.timestamp,
            "srcMac": self.src_mac,
            "dstMac": self.dst_mac,
            "srcIp": self.src_ip,
            "dstIp": self.dst_ip,
            "srcPort": self.src_port,
            "dstPort": self.dst_port,
            "transportProtocol": self.transport_protocol,
            "networkProtocol": self.network_protocol,
            "length": self.packet_length,
            "tcpFlags": self.tcp_flags,
            "ttl": self.ttl,
            "payloadPreview": self.payload_preview,
            "protocolInfo": self.protocol_info,
            "httpMeta": self.http_meta,
            "dnsMeta": self.dns_meta,
            "tlsMeta": self.tls_meta,
            "icmpMeta": self.icmp_meta,
        }


def _first_val(data: Any, *keys: str, default: Any = "") -> Any:
    """Helper to safely retrieve value from nested dict/list structures produced by TShark."""
    if not isinstance(data, dict):
        return default
    for key in keys:
        if key in data:
            val = data[key]
            if isinstance(val, list) and val:
                return val[0]
            if val is not None:
                return val
    return default


def parse_tshark_frame(frame: dict[str, Any], frame_counter: int = 0) -> Optional[ParsedPacket]:
    """
    Parse a single TShark JSON/EK object into a normalized ParsedPacket.
    Returns None if the frame does not contain valid network/transport layers (e.g. EK index header lines).
    """
    if not isinstance(frame, dict):
        return None

    # TShark EK format uses "layers" or "_source.layers"
    layers = frame.get("layers") or frame.get("_source", {}).get("layers")
    if not layers or not isinstance(layers, dict):
        return None

    try:
        # 1. Frame metadata
        frame_layer = layers.get("frame", {})
        f_num_raw = _first_val(frame_layer, "frame_frame_number", "frame.number", default=frame_counter)
        frame_number = int(f_num_raw) if str(f_num_raw).isdigit() else frame_counter

        ts_raw = _first_val(frame_layer, "frame_frame_time_epoch", "frame.time_epoch", default=time.time())
        try:
            timestamp = float(ts_raw)
        except (ValueError, TypeError):
            timestamp = time.time()

        pkt_len_raw = _first_val(frame_layer, "frame_frame_len", "frame.len", default=0)
        try:
            packet_length = int(pkt_len_raw)
        except (ValueError, TypeError):
            packet_length = 0

        # 2. Ethernet / L2
        eth_layer = layers.get("eth", {})
        src_mac = str(_first_val(eth_layer, "eth_eth_src", "eth.src", default="00:00:00:00:00:00"))
        dst_mac = str(_first_val(eth_layer, "eth_eth_dst", "eth.dst", default="00:00:00:00:00:00"))

        # 3. IP / L3
        src_ip = ""
        dst_ip = ""
        network_protocol = "IP"
        ttl = 64

        if "ip" in layers:
            ip_layer = layers["ip"]
            src_ip = str(_first_val(ip_layer, "ip_ip_src", "ip.src", default=""))
            dst_ip = str(_first_val(ip_layer, "ip_ip_dst", "ip.dst", default=""))
            network_protocol = "IPv4"
            ttl_raw = _first_val(ip_layer, "ip_ip_ttl", "ip.ttl", default=64)
            try:
                ttl = int(ttl_raw)
            except (ValueError, TypeError):
                ttl = 64
        elif "ipv6" in layers:
            v6_layer = layers["ipv6"]
            src_ip = str(_first_val(v6_layer, "ipv6_ipv6_src", "ipv6.src", default=""))
            dst_ip = str(_first_val(v6_layer, "ipv6_ipv6_dst", "ipv6.dst", default=""))
            network_protocol = "IPv6"
            hlim_raw = _first_val(v6_layer, "ipv6_ipv6_hlim", "ipv6.hlim", default=64)
            try:
                ttl = int(hlim_raw)
            except (ValueError, TypeError):
                ttl = 64
        elif "arp" in layers:
            arp_layer = layers["arp"]
            src_ip = str(_first_val(arp_layer, "arp_arp_src_proto_ipv4", "arp.src.proto_ipv4", default=""))
            dst_ip = str(_first_val(arp_layer, "arp_arp_dst_proto_ipv4", "arp.dst.proto_ipv4", default=""))
            network_protocol = "ARP"

        if not src_ip and not dst_ip:
            # Skip non-IP / non-ARP raw frames
            return None

        # 4. Transport Layer (TCP, UDP, ICMP)
        src_port = 0
        dst_port = 0
        transport_protocol = "OTHER"
        tcp_flags: dict[str, bool] = {"syn": False, "ack": False, "fin": False, "rst": False, "psh": False}

        if "tcp" in layers:
            tcp_layer = layers["tcp"]
            transport_protocol = "TCP"
            sp_raw = _first_val(tcp_layer, "tcp_tcp_srcport", "tcp.srcport", default=0)
            dp_raw = _first_val(tcp_layer, "tcp_tcp_dstport", "tcp.dstport", default=0)
            try:
                src_port = int(sp_raw)
                dst_port = int(dp_raw)
            except (ValueError, TypeError):
                pass

            # Extract flags if available
            flags_raw = _first_val(tcp_layer, "tcp_tcp_flags_tree", "tcp.flags_tree", default={})
            if isinstance(flags_raw, dict):
                tcp_flags["syn"] = bool(_first_val(flags_raw, "tcp_tcp_flags_syn", "tcp.flags.syn", default=0))
                tcp_flags["ack"] = bool(_first_val(flags_raw, "tcp_tcp_flags_ack", "tcp.flags.ack", default=0))
                tcp_flags["fin"] = bool(_first_val(flags_raw, "tcp_tcp_flags_fin", "tcp.flags.fin", default=0))
                tcp_flags["rst"] = bool(_first_val(flags_raw, "tcp_tcp_flags_reset", "tcp.flags.reset", default=0))
                tcp_flags["psh"] = bool(_first_val(flags_raw, "tcp_tcp_flags_push", "tcp.flags.push", default=0))
            else:
                # Raw hex flags
                hex_flags = str(_first_val(tcp_layer, "tcp_tcp_flags", "tcp.flags", default="0"))
                try:
                    val = int(hex_flags, 16) if hex_flags.startswith("0x") else int(hex_flags)
                    tcp_flags["fin"] = bool(val & 0x01)
                    tcp_flags["syn"] = bool(val & 0x02)
                    tcp_flags["rst"] = bool(val & 0x04)
                    tcp_flags["psh"] = bool(val & 0x08)
                    tcp_flags["ack"] = bool(val & 0x10)
                except (ValueError, TypeError):
                    pass

        elif "udp" in layers:
            udp_layer = layers["udp"]
            transport_protocol = "UDP"
            sp_raw = _first_val(udp_layer, "udp_udp_srcport", "udp.srcport", default=0)
            dp_raw = _first_val(udp_layer, "udp_udp_dstport", "udp.dstport", default=0)
            try:
                src_port = int(sp_raw)
                dst_port = int(dp_raw)
            except (ValueError, TypeError):
                pass

        elif "icmp" in layers:
            transport_protocol = "ICMP"

        # 5. Application Layer & Protocol Metadata
        http_meta: Optional[dict[str, Any]] = None
        dns_meta: Optional[dict[str, Any]] = None
        tls_meta: Optional[dict[str, Any]] = None
        icmp_meta: Optional[dict[str, Any]] = None
        info_parts: list[str] = [f"{transport_protocol}"]

        if "http" in layers:
            http = layers["http"]
            host = str(_first_val(http, "http_http_host", "http.host", default=""))
            method = str(_first_val(http, "http_http_request_method", "http.request.method", default=""))
            uri = str(_first_val(http, "http_http_request_uri", "http.request.uri", default=""))
            if host or method:
                http_meta = {"host": host, "method": method, "uri": uri}
                info_parts.append(f"HTTP {method} {host}{uri}" if method else f"HTTP Host: {host}")

        if "dns" in layers:
            dns = layers["dns"]
            qname = str(_first_val(dns, "dns_dns_qry_name", "dns.qry.name", default=""))
            qtype = str(_first_val(dns, "dns_dns_qry_type", "dns.qry.type", default="A"))
            if qname:
                dns_meta = {"query": qname, "qtype": qtype}
                info_parts.append(f"DNS Q: {qname}")

        if "tls" in layers or "ssl" in layers:
            tls = layers.get("tls") or layers.get("ssl") or {}
            sni = str(_first_val(tls, "tls_tls_handshake_extensions_server_name", "tls.handshake.extensions_server_name", default=""))
            version = str(_first_val(tls, "tls_tls_record_version", "tls.record.version", default="TLSv1.2"))
            tls_meta = {"sni": sni or None, "version": version}
            info_parts.append(f"TLS SNI: {sni}" if sni else "TLS Encrypted Handshake")

        if "icmp" in layers:
            icmp = layers["icmp"]
            itype = _first_val(icmp, "icmp_icmp_type", "icmp.type", default=8)
            icode = _first_val(icmp, "icmp_icmp_code", "icmp.code", default=0)
            icmp_meta = {"type": itype, "code": icode}
            info_parts.append(f"ICMP type={itype} code={icode}")

        # 6. Payload Preview (Privacy Controlled & Bounded)
        payload_preview = ""
        raw_data = _first_val(layers, "data_data_data", "data.data", "tcp_tcp_payload", "tcp.payload", default="")
        if raw_data:
            s_data = str(raw_data).replace(":", "")
            preview_len = min(len(s_data), MAX_PAYLOAD_BYTES * 2)
            payload_preview = s_data[:preview_len]

        protocol_info = " · ".join(info_parts) if len(info_parts) > 1 else f"{transport_protocol} packet ({packet_length} bytes)"

        return ParsedPacket(
            frame_number=frame_number,
            timestamp=timestamp,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport_protocol=transport_protocol,
            network_protocol=network_protocol,
            packet_length=packet_length,
            tcp_flags=tcp_flags,
            ttl=ttl,
            payload_preview=payload_preview,
            protocol_info=protocol_info,
            http_meta=http_meta,
            dns_meta=dns_meta,
            tls_meta=tls_meta,
            icmp_meta=icmp_meta,
        )
    except Exception as e:
        logger.debug("Failed to parse TShark frame: %s", e)
        return None
