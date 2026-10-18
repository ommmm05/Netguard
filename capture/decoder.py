"""
Decode a Scapy packet into `IngestSnapshot` updates (passive, no injection).
"""

from __future__ import annotations

import re
from struct import unpack

from scapy.all import (
    IP,
    TCP,
    UDP,
    Raw,
)
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

from visibility.ingest_state import IngestSnapshot
from visibility.tls_sni import extract_tls_sni_from_payload

_HTTP_HOST = re.compile(rb"host:\s*([^\r\n]+)\r\n", re.I)


def _wire_len(pkt) -> int:
    try:
        return int(len(bytes(pkt)))
    except Exception:
        return 0


def _http_host_from_raw(data: bytes) -> str | None:
    m = _HTTP_HOST.search(data)
    if m:
        return m.group(1).decode("utf-8", errors="ignore").strip()[:200]
    return None


def _ipv4_in_packet(pkt) -> object | None:
    if IP in pkt:
        return pkt[IP]
    return None


def process_packet(pkt, snap: IngestSnapshot) -> None:
    """Ingest a single Scapy packet into snapshot."""
    t = float(getattr(pkt, "time", 0) or 0) or 0.0
    wlen = _wire_len(pkt) or 1

    if ARP in pkt:
        a = pkt[ARP]
        try:
            if int(a.op) in (1, 2) and a.psrc and a.hwsrc:
                snap.register_arp(str(a.psrc), str(a.hwsrc), t)
        except (AttributeError, TypeError, ValueError):
            pass
        return

    ipL = _ipv4_in_packet(pkt)
    if ipL is None:
        if IPv6 in pkt:
            # Phase 1: v6 not fully attributed (no RFC1918 match); skip
            return
        return

    ip = ipL
    src, dst = str(ip.src), str(ip.dst)
    pnum = int(ip.proto)
    tos = float(t)

    if TCP in ip:
        tcp = ip[TCP]
        sport, dport = int(tcp.sport), int(tcp.dport)
        rawp = None
        if Raw in tcp:
            rawp = bytes(tcp[Raw].load)
            h = _http_host_from_raw(rawp)
            if h:
                snap.register_http_host(src, dst, h, tos)
            if dport in (443, 8443) or sport in (443, 8443):
                if rawp and len(rawp) > 8:
                    sni = extract_tls_sni_from_payload(rawp)
                    sus = not sni
                    snap.register_tls(
                        src,
                        dst,
                        sni,
                        "TLSv1.2+",
                        "—",
                        "Self-Signed" if sus else "Unknown",
                    )
        snap.register_flow(src, dst, sport, dport, pnum, "TCP", wlen, tos)
        return

    if UDP in ip:
        udp = ip[UDP]
        sport, dport = int(udp.sport), int(udp.dport)
        if DNS in udp:
            d = ip[DNS]
            try:
                if d.qd and getattr(d.qd, "qname", None):
                    name = d.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                    qt = int(getattr(d.qd, "qtype", 1) or 1)
                    qtype = {1: "A", 28: "AAAA", 16: "TXT"}.get(qt, "A")
                    ans: str | None = None
                    an = getattr(d, "an", None)
                    if an is not None and getattr(d, "ancount", 0):
                        try:
                            rdata = getattr(an, "rdata", b"")
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode(errors="ignore")
                            if isinstance(rdata, str) and re.match(
                                r"^\d{1,3}(\.\d{1,3}){3}$", rdata
                            ):
                                ans = rdata
                        except (TypeError, AttributeError):
                            pass
                    snap.register_dns(name, qtype, src, ans, tos)
            except (AttributeError, TypeError, UnicodeError):
                pass
        if DHCP in ip:
            try:
                bp: DHCP = ip[DHCP]
                host = None
                req: str | None = None
                for opt, val in bp.options:
                    if opt == 12 and isinstance(val, (bytes, bytearray)):
                        host = bytes(val).decode(errors="ignore").strip()[:200] or None
                    if opt == 50 and val and len(val) == 4:
                        req = ".".join(str(b) for b in val)
                if host:
                    snap._ensure_host(src)
                    snap.hosts[src]["hostname"] = host
                if req:
                    snap._ensure_host(req)
                    if host:
                        snap.hosts[req]["hostname"] = host
                client_ip = req
                if not client_ip:
                    yi = getattr(bp, "yiaddr", None) or getattr(bp, "ciaddr", None)
                    if yi:
                        client_ip = str(yi).strip()
                if client_ip and client_ip != "0.0.0.0":
                    server_ip = src if sport == 67 else (dst if dport == 67 else src)
                    snap.register_dhcp_observation(
                        client_ip=client_ip,
                        hostname=host,
                        server_ip=server_ip,
                        when=tos,
                    )
            except (TypeError, ValueError, AttributeError):
                pass
        snap.register_flow(src, dst, sport, dport, pnum, "UDP", wlen, tos)
        return

    if ICMP in ip:
        snap.register_flow(src, dst, 0, 0, pnum, "ICMP", wlen, tos)
        return

    snap.register_flow(src, dst, 0, 0, pnum, "IP", wlen, tos)
