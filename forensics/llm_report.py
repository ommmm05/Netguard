"""LLM-assisted incident narrative. Uses OpenAI if NETGUARD_OPENAI_KEY is set; else deterministic text."""

from __future__ import annotations

import os
from typing import Any

try:
    from openai import OpenAI
except Exception:  # noqa: BLE001
    OpenAI = None  # type: ignore[assignment, misc]


def _fallback_summary(alert: dict[str, Any], shap: dict[str, Any] | None) -> str:
    top = (shap or {}).get("top") or []
    top_line = top[0]["feature"] if top else "flow_volume"
    return (
        f"Incident {alert.get('id')}: the ensemble flagged {alert.get('attackType', 'suspicious activity')} with "
        f"confidence {alert.get('confidence', 0):.1f}%. The strongest SHAP driver is '{top_line}' for the Random Forest model, "
        f"indicating the decision was largely influenced by that flow feature rather than a single packet artifact."
    )


def generate_incident_summary(alert: dict[str, Any], shap: dict[str, Any] | None) -> str:
    key = os.environ.get("NETGUARD_OPENAI_KEY", "").strip()
    if not key or OpenAI is None:
        return _fallback_summary(alert, shap)
    try:
        client = OpenAI(api_key=key)
        r = client.chat.completions.create(
            model=os.environ.get("NETGUARD_OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {
                    "role": "system",
                    "content": "You are a SOC lead. Write 3 short paragraphs: summary, why SHAP top features matter, and immediate containment steps.",
                },
                {
                    "role": "user",
                    "content": f"alert={alert}\n shap={shap}",
                },
            ],
            temperature=0.2,
        )
        return (r.choices[0].message.content or "").strip() or _fallback_summary(alert, shap)
    except Exception:  # noqa: BLE001
        return _fallback_summary(alert, shap)


def suggest_remediation(alert: dict[str, Any]) -> list[str]:
    a = (alert.get("attackType") or "").lower()
    out = [
        f"Contain: temporarily isolate host {alert.get('srcIp')} if lateral movement is suspected",
        f"Enforce: block or rate-limit {alert.get('dstIp')} on suspicious ports at the perimeter",
        f"Monitor: keep PCAP artifacts and retain NetGuard forensics export for legal chain of custody",
    ]
    if "dos" in a or "ddos" in a:
        out.append("DDoS: engage upstream scrubbing and CDN/WAF rate limits")
    if "scan" in a:
        out.append("Scan: verify whether source host is a legitimate vulnerability scanner; if not, quarantine")
    if "anomaly" in a:
        out.append("Anomaly: compare against rolling baseline; verify business justification for the destination")
    return out
