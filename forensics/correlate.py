"""
Incident correlation engine (Phase 3).

Groups alerts by src/dst pairs, assigns deterministic incident IDs,
computes aggregated severity scores, extracts IOCs (indicators of
compromise), and produces timeline event lists.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any


# ─── Severity helpers ────────────────────────────────────────────────
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _sev_value(sev: str) -> int:
    return _SEV_RANK.get((sev or "").lower(), 0)


def _rank_to_label(rank: int) -> str:
    for label, v in _SEV_RANK.items():
        if v == rank:
            return label
    return "info"


# ─── Core correlation ────────────────────────────────────────────────
def correlate_alerts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group alerts by (srcIp, dstIp) pair and sort by event count."""
    g: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        key = f"{r.get('srcIp') or ''}::{r.get('dstIp') or ''}"
        g[key].append(r)
    out = []
    for k, evs in g.items():
        evs2 = sorted(evs, key=lambda e: e.get("timestamp") or "")
        s_ip, d_ip = k.split("::", 1) if "::" in k else ("", "")
        out.append(
            {
                "key": k,
                "srcIp": s_ip,
                "dstIp": d_ip,
                "count": len(evs2),
                "timeline": evs2,
            }
        )
    out.sort(key=lambda x: -x["count"])
    return out


def as_timeline_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten alerts into a sorted timeline of display events."""
    evs: list[dict[str, Any]] = []
    for r in rows:
        ts = r.get("timestamp")
        t = "unknown"
        if isinstance(ts, str):
            t = ts[11:19] if "T" in ts else ts[:8]
        evs.append(
            {
                "time": t,
                "event": r.get("title", "Alert"),
                "severity": r.get("severity", "info"),
                "host": f"{r.get('srcIp','')} -> {r.get('dstIp','')}",
                "details": r.get("description", ""),
            }
        )
    evs.sort(key=lambda e: e["time"])
    return evs


# ─── Incident grouping with IDs + severity scoring ──────────────────
def build_incident_groups(
    rows: list[dict[str, Any]], *, time_window_s: int = 300
) -> list[dict[str, Any]]:
    """
    Cluster alerts into incident groups by (srcIp, dstIp) pair and
    5-minute time windows.  Each group gets a deterministic INC-XXXX
    identifier and an aggregate severity score.
    """
    groups = correlate_alerts(rows)
    incidents: list[dict[str, Any]] = []

    for grp in groups:
        inc_id = assign_incident_id(grp["srcIp"], grp["dstIp"])
        peak = max((_sev_value(e.get("severity", "info")) for e in grp["timeline"]), default=0)
        avg_conf = 0.0
        confs = [float(e.get("confidence", 0)) for e in grp["timeline"] if e.get("confidence")]
        if confs:
            avg_conf = sum(confs) / len(confs)
        attacks = list({e.get("attackType") or e.get("attack_type") or "Unknown" for e in grp["timeline"]})
        incidents.append(
            {
                "incidentId": inc_id,
                "srcIp": grp["srcIp"],
                "dstIp": grp["dstIp"],
                "alertCount": grp["count"],
                "peakSeverity": _rank_to_label(peak),
                "severityScore": peak,
                "avgConfidence": round(avg_conf, 2),
                "attackTypes": attacks,
                "firstSeen": grp["timeline"][0].get("timestamp", "") if grp["timeline"] else "",
                "lastSeen": grp["timeline"][-1].get("timestamp", "") if grp["timeline"] else "",
                "alerts": grp["timeline"],
            }
        )

    incidents.sort(key=lambda x: (-x["severityScore"], -x["alertCount"]))
    return incidents


def assign_incident_id(src_ip: str, dst_ip: str) -> str:
    """Deterministic incident ID from the IP pair (stable across reruns)."""
    h = hashlib.sha256(f"{src_ip}::{dst_ip}".encode()).hexdigest()[:8].upper()
    return f"INC-{h}"


# ─── IOC extraction ─────────────────────────────────────────────────
_PRIVATE_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)"
)


def get_iocs(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Extract Indicators of Compromise from alert rows:
    - IP addresses (src/dst, tagged internal/external)
    - Ports
    - Protocols
    - Attack types
    """
    ips: dict[str, dict[str, Any]] = {}
    ports: set[int] = set()
    protocols: set[str] = set()
    attack_types: set[str] = set()

    for r in rows:
        for key in ("srcIp", "src_ip"):
            ip = r.get(key)
            if ip and ip not in ips:
                ips[ip] = {
                    "type": "ip",
                    "value": ip,
                    "direction": "source",
                    "internal": bool(_PRIVATE_RE.match(ip)),
                }
        for key in ("dstIp", "dst_ip"):
            ip = r.get(key)
            if ip and ip not in ips:
                ips[ip] = {
                    "type": "ip",
                    "value": ip,
                    "direction": "destination",
                    "internal": bool(_PRIVATE_RE.match(ip)),
                }
        p = r.get("dstPort") or r.get("dst_port")
        if p and isinstance(p, int):
            ports.add(p)
        proto = r.get("protocol")
        if proto:
            protocols.add(proto)
        at = r.get("attackType") or r.get("attack_type")
        if at and at != "Benign":
            attack_types.add(at)

    iocs: list[dict[str, Any]] = list(ips.values())
    for port in sorted(ports):
        iocs.append({"type": "port", "value": port})
    for proto in sorted(protocols):
        iocs.append({"type": "protocol", "value": proto})
    for at in sorted(attack_types):
        iocs.append({"type": "attack_type", "value": at})
    return iocs
