"""
Analyst assistant / chat service (Phase 3).

Provides:
  - ``analyst_chat()``  — conversational Q&A backed by OpenAI (or offline fallback).
  - ``suggest_playbook()`` — MITRE ATT&CK–based playbook suggestions.
  - ``get_mitre_mapping()`` — map NetGuard attack labels to MITRE technique IDs.
  - ``extract_iocs_from_alerts()`` — structured IOC extraction for the chat context.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Any

from forensics.correlate import as_timeline_events, get_iocs
from forensics.llm_report import _fallback_summary

try:
    from openai import OpenAI
except Exception:  # noqa: BLE001
    OpenAI = None  # type: ignore[assignment, misc]


# ─── MITRE ATT&CK mapping ───────────────────────────────────────────
_MITRE_MAP: dict[str, list[dict[str, str]]] = {
    "DoS": [
        {"technique": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
        {"technique": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
    ],
    "DDoS": [
        {"technique": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    ],
    "PortScan": [
        {"technique": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        {"technique": "T1018", "name": "Remote System Discovery", "tactic": "Discovery"},
    ],
    "BruteForce": [
        {"technique": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"technique": "T1078", "name": "Valid Accounts", "tactic": "Persistence"},
    ],
    "Anomaly": [
        {"technique": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"technique": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    ],
}

_PLAYBOOKS: dict[str, list[str]] = {
    "DoS": [
        "1. Confirm the attack: verify sustained high-volume traffic targeting the victim IP.",
        "2. Engage upstream ISP or enable cloud-based DDoS scrubbing.",
        "3. Apply rate-limiting rules at the perimeter firewall.",
        "4. Monitor for secondary attacks while the primary is being mitigated.",
        "5. Preserve PCAP artifacts for forensic analysis and legal evidence.",
    ],
    "PortScan": [
        "1. Identify the scanning source IP and verify whether it is an authorized vulnerability scanner.",
        "2. If unauthorized, block the source IP at the perimeter firewall.",
        "3. Audit exposed services on the scanned host for unnecessary open ports.",
        "4. Review IDS/IPS signatures for follow-up exploitation attempts.",
        "5. Document the scan timeframe and scope for the incident report.",
    ],
    "BruteForce": [
        "1. Immediately lock or throttle the targeted account(s).",
        "2. Block the attacking source IP at WAF / firewall level.",
        "3. Enforce multi-factor authentication (MFA) on all exposed services.",
        "4. Review authentication logs for successful logins from the attacker IP.",
        "5. Reset credentials for any accounts that may have been compromised.",
    ],
    "Anomaly": [
        "1. Compare the flagged traffic against the rolling baseline for the source host.",
        "2. Verify business justification for the destination and protocol in use.",
        "3. Check for data exfiltration indicators (large outbound transfers, unusual ports).",
        "4. Isolate the host if lateral movement is suspected.",
        "5. Escalate to threat hunting team for deeper investigation.",
    ],
}


def get_mitre_mapping(attack_type: str) -> list[dict[str, str]]:
    """Return MITRE ATT&CK techniques for a NetGuard attack label."""
    for key, techniques in _MITRE_MAP.items():
        if key.lower() in (attack_type or "").lower():
            return techniques
    return [{"technique": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}]


def suggest_playbook(attack_type: str) -> list[str]:
    """Return an ordered playbook for the given attack type."""
    for key, steps in _PLAYBOOKS.items():
        if key.lower() in (attack_type or "").lower():
            return steps
    return [
        "1. Triage: assess blast radius and affected assets.",
        "2. Contain: isolate affected hosts if necessary.",
        "3. Investigate: correlate with SHAP and timeline data in NetGuard.",
        "4. Remediate: apply patches, firewall rules, or credential resets.",
        "5. Report: generate forensic PDF for stakeholders.",
    ]


# ─── IOC extraction helper ──────────────────────────────────────────
def extract_iocs_from_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Wrapper around correlate.get_iocs for the chat context."""
    return get_iocs(alerts)


# ─── Analyst chat ────────────────────────────────────────────────────
def analyst_chat(
    user_message: str, alerts: list[dict[str, Any]], history: list[dict[str, str]] | None = None
) -> str:
    """
    Simple analyst Q&A.  Uses OpenAI if NETGUARD_OPENAI_KEY is set,
    otherwise returns rich template answers grounded in the latest alerts.
    """
    ctx = " ; ".join(
        f"{a.get('id')}: {a.get('title')} sev={a.get('severity')} src={a.get('srcIp')}"
        for a in alerts[:12]
    )
    key = os.environ.get("NETGUARD_OPENAI_KEY", "").strip()
    if key and OpenAI is not None:
        try:
            c = OpenAI(api_key=key)
            r = c.chat.completions.create(
                model=os.environ.get("NETGUARD_OPENAI_MODEL", "gpt-4o-mini"),
                temperature=0.2,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a SOC copilot for NetGuard. Answer tersely with actionable guidance. Cite source IPs. "
                        f"Context alerts: {ctx}",
                    },
                    *(
                        [
                            {"role": h["role"], "content": h["content"]}
                            for h in (history or [])[-6:]
                        ]
                    ),
                    {"role": "user", "content": user_message},
                ],
            )
            return (r.choices[0].message.content or "").strip() or "No model output."
        except Exception:  # noqa: BLE001
            pass

    # ── Offline fallback with richer template answers ──
    u = user_message.lower()

    if "mitre" in u or "att&ck" in u or "technique" in u:
        if alerts:
            at = alerts[0].get("attackType") or alerts[0].get("attack_type") or "Anomaly"
            mapping = get_mitre_mapping(at)
            lines = [f"MITRE ATT&CK mapping for '{at}':"]
            for m in mapping:
                lines.append(f"  • {m['technique']} — {m['name']} ({m['tactic']})")
            return "\n".join(lines)
        return "No alerts loaded yet. Ingest a PCAP and run detection first."

    if "playbook" in u or "respond" in u or "contain" in u:
        if alerts:
            at = alerts[0].get("attackType") or alerts[0].get("attack_type") or "Anomaly"
            steps = suggest_playbook(at)
            return f"Playbook for '{at}':\n" + "\n".join(steps)
        return "No alerts available. Run /api/detection/scan after PCAP ingest."

    if "ioc" in u or "indicator" in u:
        iocs = extract_iocs_from_alerts(alerts)
        if not iocs:
            return "No IOCs extracted — run detection scan first."
        lines = ["Extracted IOCs:"]
        for ioc in iocs[:15]:
            lines.append(f"  • [{ioc['type']}] {ioc['value']}")
        return "\n".join(lines)

    if "timeline" in u:
        t = as_timeline_events(alerts)
        if not t:
            return "No alert timeline yet — run /api/detection/scan after PCAP ingest."
        return "Timeline: " + "; ".join(
            f"{e['time']} {e['event']} ({e['severity']})" for e in t[:8]
        )

    if "summary" in u or "top" in u:
        if not alerts:
            return "No alerts in database yet."
        a0 = alerts[0]
        return _fallback_summary(
            {k: a0.get(k) for k in ("id", "title", "attackType", "confidence", "srcIp", "dstIp")},
            None,
        )

    if "shap" in u:
        return "Open an alert in Forensics to compute SHAP for that row; SHAP is tree-specific (Random Forest primary)."

    return f"(Offline analyst mode) You asked: {user_message!r}. Current highest-severity open items: {ctx or 'none'}."


# ─── Helpers ─────────────────────────────────────────────────────────
def new_report_id() -> str:
    return f"RPT-{uuid.uuid4().hex[:8].upper()}"


def utc_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
