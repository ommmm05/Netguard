"""Forensic intelligence: SHAP, LLM text, export, timeline, IOCs, chat (Phase 3)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database_deps import get_db
from database.models import ForensicReport, MLAlert
from database.session import init_db
from forensics.chat_service import (
    analyst_chat,
    extract_iocs_from_alerts,
    get_mitre_mapping,
    new_report_id,
    suggest_playbook,
    utc_iso,
)
from forensics.correlate import as_timeline_events, build_incident_groups, correlate_alerts, get_iocs
from forensics.exporter import build_forensic_pdf, build_simple_pdf, export_alerts_csv
from forensics.llm_report import generate_incident_summary, suggest_remediation
from forensics.shap_explain import shap_explain_for_row
from forensics.feature_importance import global_feature_importance
from forensics.timeline import build_full_timeline

router = APIRouter(prefix="/forensics", tags=["forensics"])


# ─── Helpers ─────────────────────────────────────────────────────────
def _alert_to_dict(r: MLAlert) -> dict[str, Any]:
    return {
        "id": r.id,
        "title": r.title,
        "severity": r.severity,
        "timestamp": r.created_at.replace(tzinfo=None).isoformat() + "Z" if r.created_at else None,
        "srcIp": r.src_ip,
        "dstIp": r.dst_ip,
        "description": r.description,
        "attackType": r.attack_type,
        "confidence": r.confidence,
        "model": r.model,
        "status": r.status,
        "features": r.features,
    }


def _load_alerts(session: Session, limit: int = 200) -> list[dict[str, Any]]:
    init_db()
    q = select(MLAlert).order_by(MLAlert.created_at.desc()).limit(max(1, min(limit, 2000)))
    rows = list(session.execute(q).scalars().all())
    return [_alert_to_dict(r) for r in rows]


# ─── Global feature importance (Phase 3 charting) ──────────────────
@router.get("/feature-importance")
def feature_importance() -> dict:
    """CICIDS-aligned global weights for dashboard (SHAP remains per-alert)."""
    return {"ok": True, "source": "cicids2017_subset+synthetic_weights", "items": global_feature_importance()}


# ─── Alert listing ───────────────────────────────────────────────────
@router.get("/alerts")
def all_alerts(session: Session = Depends(get_db), limit: int = 200) -> dict:
    return {"alerts": _load_alerts(session, limit)}


# ─── SHAP explainability ────────────────────────────────────────────
@router.get("/alert/{aid}/shap")
def get_shap(aid: str, session: Session = Depends(get_db)) -> dict:
    init_db()
    a = session.get(MLAlert, aid)
    if a is None:
        raise HTTPException(404, "alert not found")
    out = shap_explain_for_row(dict(a.features or {}))
    a.shap_top = out.get("top")
    return {"ok": True, "alertId": aid, "explanation": out}


# ─── Forensic report generation ─────────────────────────────────────
class ReportBody(BaseModel):
    with_llm: bool = True


@router.post("/alert/{aid}/report")
def build_report(
    aid: str, body: ReportBody, session: Session = Depends(get_db)
) -> dict:
    init_db()
    a = session.get(MLAlert, aid)
    if a is None:
        raise HTTPException(404, "alert not found")
    shp = shap_explain_for_row(dict(a.features or {}))
    alert = {
        "id": a.id,
        "title": a.title,
        "attackType": a.attack_type,
        "confidence": a.confidence,
        "srcIp": a.src_ip,
        "dstIp": a.dst_ip,
        "description": a.description,
    }
    if body.with_llm:
        summ2 = generate_incident_summary(alert, shp)
    else:
        summ2 = f"Offline summary: {a.title} ({a.attack_type}) {a.src_ip} → {a.dst_ip} (confidence {a.confidence})."
    rem = suggest_remediation(
        {**alert, "attackType": a.attack_type, "srcIp": a.src_ip, "dstIp": a.dst_ip}
    )
    tl = as_timeline_events(
        [
            {
                "timestamp": a.created_at.replace(tzinfo=None).isoformat() + "Z" if a.created_at else None,
                "title": a.title,
                "severity": a.severity,
                "srcIp": a.src_ip,
                "dstIp": a.dst_ip,
                "description": a.description,
            }
        ]
    )
    rep = ForensicReport(
        id=new_report_id(),
        alert_id=a.id,
        summary_text=summ2,
        remediation=rem,
        timeline=tl,
        shap_plot_base64=None,
    )
    session.add(rep)
    return {
        "ok": True,
        "report": {
            "id": rep.id,
            "summary": rep.summary_text,
            "remediation": rem,
            "timeline": tl,
            "shap": shp,
        },
    }


# ─── Incident correlation ───────────────────────────────────────────
@router.get("/incidents")
def incidents(session: Session = Depends(get_db), limit: int = 200) -> dict:
    al = _load_alerts(session, limit=limit)
    return {"groups": build_incident_groups(al)}


# ─── Incident timeline ──────────────────────────────────────────────
@router.get("/timeline/{aid}")
def alert_timeline(aid: str, session: Session = Depends(get_db)) -> dict:
    """
    Build a full incident timeline anchored on a specific alert.
    Includes all related alerts from the same src/dst pair.
    """
    init_db()
    a = session.get(MLAlert, aid)
    if a is None:
        raise HTTPException(404, "alert not found")

    # Find all alerts involving the same IPs
    q = select(MLAlert).where(
        (MLAlert.src_ip == a.src_ip) | (MLAlert.dst_ip == a.dst_ip)
    ).order_by(MLAlert.created_at.asc()).limit(50)
    related = list(session.execute(q).scalars().all())

    alert_dicts = [_alert_to_dict(r) for r in related]
    tl = build_full_timeline(alert_dicts)
    return {"ok": True, "alertId": aid, "timeline": tl.to_dict()}


# ─── IOC extraction ─────────────────────────────────────────────────
@router.get("/iocs")
def ioc_list(session: Session = Depends(get_db), limit: int = 200) -> dict:
    """Extract Indicators of Compromise from all alerts."""
    al = _load_alerts(session, limit)
    return {"iocs": get_iocs(al), "alertCount": len(al)}


# ─── MITRE ATT&CK mapping ───────────────────────────────────────────
@router.get("/mitre/{aid}")
def mitre_mapping(aid: str, session: Session = Depends(get_db)) -> dict:
    """Map a specific alert to MITRE ATT&CK techniques."""
    init_db()
    a = session.get(MLAlert, aid)
    if a is None:
        raise HTTPException(404, "alert not found")
    mapping = get_mitre_mapping(a.attack_type or "")
    playbook = suggest_playbook(a.attack_type or "")
    return {
        "ok": True,
        "alertId": aid,
        "attackType": a.attack_type,
        "mitre": mapping,
        "playbook": playbook,
    }


# ─── CSV export ──────────────────────────────────────────────────────
@router.get("/export/csv")
def export_csv(
    session: Session = Depends(get_db), ids: str = Query("", description="Comma-separated alert ids, empty = all")
) -> Response:
    init_db()
    q = select(MLAlert).order_by(MLAlert.created_at.desc()).limit(5000)
    rows = list(session.execute(q).scalars().all())
    want = {x for x in ids.split(",") if x} if ids else None
    out_rows = [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity,
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "attack_type": r.attack_type,
            "confidence": r.confidence,
            "status": r.status,
        }
        for r in rows
        if not want or r.id in want
    ]
    data = export_alerts_csv(out_rows)
    return Response(content=data, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=alerts.csv"})


# ─── PDF export (enhanced) ──────────────────────────────────────────
@router.get("/export/pdf")
def export_pdf(alert_id: str = Query(..., description="ML alert id"), session: Session = Depends(get_db)) -> Response:
    init_db()
    a = session.get(MLAlert, alert_id)
    if a is None:
        raise HTTPException(404, "not found")
    shp = shap_explain_for_row(dict(a.features or {}))
    alert_dict = {
        "id": a.id,
        "title": a.title,
        "severity": a.severity,
        "attackType": a.attack_type,
        "confidence": a.confidence,
        "srcIp": a.src_ip,
        "dstIp": a.dst_ip,
        "description": a.description,
        "model": a.model,
    }
    narrative = generate_incident_summary(alert_dict, shp)
    rem = suggest_remediation(alert_dict)
    tl = as_timeline_events([{
        "timestamp": a.created_at.replace(tzinfo=None).isoformat() + "Z" if a.created_at else None,
        "title": a.title,
        "severity": a.severity,
        "srcIp": a.src_ip,
        "dstIp": a.dst_ip,
        "description": a.description,
    }])

    pdf = build_forensic_pdf(
        alert=alert_dict,
        shap_top=shp.get("top"),
        timeline=tl,
        remediation=rem,
        narrative=narrative,
        report_id=new_report_id(),
    )
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=netguard-{a.id}.pdf"},
    )


# ─── Analyst chat ────────────────────────────────────────────────────
class ChatBody(BaseModel):
    message: str = Field(..., min_length=1)
    history: list[dict[str, str]] = Field(default_factory=list)


@router.post("/chat")
def chat(
    body: ChatBody, session: Session = Depends(get_db)
) -> dict:
    al = _load_alerts(session, 50)
    reply = analyst_chat(body.message, al, body.history)
    return {"ok": True, "reply": reply, "at": utc_iso()}
