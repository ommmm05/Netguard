"""
Passive heuristics for suspicious communication patterns.
No active probing; uses flow shape, port semantics, and ARP/DNS signals only.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from typing import Any, Optional

from visibility.network_utils import is_rfc1918


# Domains that look like DGAs / random labels (very rough, demo-grade)
def dns_looks_suspicious(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    if re.search(r"malware|exfil|bot|c2|onion|darkweb", d):
        return True
    parts = d.split(".")
    if len(parts) < 2:
        return False
    label0 = parts[0]
    if len(label0) > 30 and re.match(r"^[a-z0-9-]+$", label0) and label0.count("-") < 2:
        # long single token subdomain could be DGA-like
        return len(label0) > 40
    return False


def flow_threat_flags(
    proto: str,
    src_port: int,
    dst_port: int,
    duration_s: float,
    bytes_total: int,
    packets: int,
    src_ip: str,
    dst_ip: str,
) -> tuple[Optional[str], str, bool]:
    """
    Return (threat_label_or_none, severity, suspicious).
    """
    d = dst_port
    s = src_port
    sev = "info"
    threat: Optional[str] = None
    suspicious = False

    if proto in ("TCP", "UDP") and d in (4444, 1337, 31337, 9001, 6667):
        threat, sev, suspicious = "C2 / backdoor-suspect", "high", True

    if proto == "TCP" and d == 3389 and (not is_rfc1918(src_ip)) and is_rfc1918(dst_ip):
        threat, sev, suspicious = "RDP to internal from external", "critical", True

    if proto == "TCP" and d == 445 and bytes_total > 2_000_000 and duration_s > 60:
        threat, sev, suspicious = "SMB long session", "high", True

    if proto == "TCP" and s > 30000 and d in range(1, 1025) and packets > 200 and duration_s < 30:
        threat, sev, suspicious = "Port scan pattern", "high", True

    if proto in ("TCP", "UDP") and bytes_total > 50_000_000 and duration_s > 3600 and d > 10000:
        threat, sev, suspicious = "Long-haul high-port session", "medium", True

    return threat, sev, suspicious


def arp_spoof_risk(arp_ip_to_macs: dict[str, list[str]]) -> dict[str, bool]:
    """If same IP seen with 2+ MACs, mark conflict rows."""
    out: dict[str, bool] = {}
    for ip, macs in arp_ip_to_macs.items():
        uniq = {m.lower() for m in macs if m}
        out[ip] = len(uniq) > 1
    return out
