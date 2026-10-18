"""
Incident timeline builder (Phase 3).

Constructs a chronological narrative from one or more ML alerts and
their associated flow metadata.  Used by the forensics API and PDF
exporter to render the "Incident Timeline" section of a report.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# ─── Kill-chain phase inference ──────────────────────────────────────
_PHASE_MAP: dict[str, str] = {
    "PortScan":   "Reconnaissance",
    "BruteForce": "Initial Access",
    "DoS":        "Impact",
    "DDoS":       "Impact",
    "Anomaly":    "Lateral Movement / Exfiltration",
    "Benign":     "Normal Traffic",
}


def _infer_phase(attack_type: str) -> str:
    for key, phase in _PHASE_MAP.items():
        if key.lower() in (attack_type or "").lower():
            return phase
    return "Unknown"


def _severity_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
        (sev or "").lower(), 0
    )


# ─── Timeline event ─────────────────────────────────────────────────
@dataclass
class TimelineEvent:
    timestamp: str
    title: str
    severity: str
    src_ip: str
    dst_ip: str
    phase: str
    description: str = ""
    alert_id: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "title": self.title,
            "severity": self.severity,
            "srcIp": self.src_ip,
            "dstIp": self.dst_ip,
            "phase": self.phase,
            "description": self.description,
            "alertId": self.alert_id,
            "confidence": self.confidence,
        }


# ─── Timeline builder ───────────────────────────────────────────────
@dataclass
class IncidentTimeline:
    """
    Aggregates multiple alert dicts into a sorted, phase-annotated
    timeline suitable for report rendering and API response.
    """

    incident_id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    events: list[TimelineEvent] = field(default_factory=list)
    peak_severity: str = "info"

    def add_alert(self, alert: dict[str, Any]) -> None:
        ts = alert.get("timestamp") or alert.get("created_at") or ""
        if isinstance(ts, datetime):
            ts = ts.replace(microsecond=0).isoformat() + "Z"
        evt = TimelineEvent(
            timestamp=str(ts),
            title=alert.get("title", "Alert"),
            severity=alert.get("severity", "info"),
            src_ip=alert.get("srcIp") or alert.get("src_ip") or "",
            dst_ip=alert.get("dstIp") or alert.get("dst_ip") or "",
            phase=_infer_phase(alert.get("attackType") or alert.get("attack_type") or ""),
            description=alert.get("description", ""),
            alert_id=alert.get("id", ""),
            confidence=float(alert.get("confidence", 0)),
        )
        self.events.append(evt)
        if _severity_rank(evt.severity) > _severity_rank(self.peak_severity):
            self.peak_severity = evt.severity

    def sort(self) -> None:
        self.events.sort(key=lambda e: e.timestamp)

    def to_dict(self) -> dict[str, Any]:
        self.sort()
        return {
            "incidentId": self.incident_id,
            "peakSeverity": self.peak_severity,
            "eventCount": len(self.events),
            "events": [e.to_dict() for e in self.events],
            "phases": list(dict.fromkeys(e.phase for e in self.events)),
        }

    def to_mermaid(self) -> str:
        """Render a Mermaid Gantt-style timeline for documentation/export."""
        self.sort()
        lines = ["gantt", "    title Incident Timeline", "    dateFormat HH:mm:ss"]
        for i, e in enumerate(self.events):
            time_part = e.timestamp[11:19] if "T" in e.timestamp else "00:00:00"
            label = e.title.replace('"', "'")[:40]
            lines.append(f'    {label} :{time_part}, 1s')
        return "\n".join(lines)


# ─── Convenience builder ─────────────────────────────────────────────
def build_full_timeline(
    alerts: list[dict[str, Any]],
    flows: list[dict[str, Any]] | None = None,
) -> IncidentTimeline:
    """
    Build a timeline from alert dicts plus optional flow metadata.
    Flow entries are added as supporting context events.
    """
    tl = IncidentTimeline()
    for a in alerts:
        tl.add_alert(a)

    if flows:
        for f in flows:
            tl.add_alert({
                "timestamp": f.get("startTime", ""),
                "title": f"Flow: {f.get('srcIp','')} → {f.get('dstIp','')}:{f.get('dstPort','')}",
                "severity": f.get("severity", "info"),
                "srcIp": f.get("srcIp", ""),
                "dstIp": f.get("dstIp", ""),
                "attackType": f.get("threat") or "Benign",
                "description": f"Protocol {f.get('protocol','')} | {f.get('packets',0)} pkts | {f.get('bytes',0)} bytes",
                "id": f.get("id", ""),
                "confidence": 0,
            })

    tl.sort()
    return tl
