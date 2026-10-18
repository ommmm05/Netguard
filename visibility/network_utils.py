"""IP helpers: RFC1918, displayable filter, protocol naming."""

from __future__ import annotations

import ipaddress
from typing import Optional

PROTO_MAP = {
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP",
    8443: "HTTPS",
    502: "Modbus",
    20000: "DNP3",
    102: "S7comm",
    44818: "EtherNet/IP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    161: "SNMP",
    67: "DHCP",
    68: "DHCP",
    445: "SMB",
    3389: "RDP",
    1883: "MQTT",
}


def is_rfc1918(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    a, b, *_ = (int(x) for x in addr.split("."))
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    return False


def is_displayable_ip(addr: str) -> bool:
    """Strip loopback / link-local / unspecified from topology display."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return False
    # Explicit strips called out in Phase 1 requirements
    a = int(str(ip).split(".", 1)[0])
    if a == 127:
        return False
    if str(ip).startswith("169.254."):
        return False
    return True


def protocol_label(l4: str, dport: int, sport: int) -> str:
    """Map flow to a dashboard-friendly L7-ish label (passive heuristics by port)."""
    if l4 == "ICMP":
        return "ICMP"
    if l4 == "ARP":
        return "ARP"
    if l4 == "Other":
        return "Other"

    for port in (dport, sport):
        if port and port in PROTO_MAP:
            return PROTO_MAP[port]

    if l4 == "TCP":
        return "TCP"
    if l4 == "UDP":
        return "UDP"
    return l4 or "Other"


def detect_protocol_from_ports(l4: str, dport: int, sport: int = 0) -> str:
    """Alias matching the Phase 1 prompt naming."""
    return protocol_label(l4, dport, sport)
