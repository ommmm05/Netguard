"""Aggregated dashboard data for Overview + Settings status."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database_deps import get_db
from database.models import MLAlert
from database.session import init_db
from detection.trainer import ensure_models
from visibility.service import get_visibility_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _threat_score(crit: int, high: int, med: int) -> int:
    return min(99, int(18 + crit * 14 + high * 6 + med * 2))


@router.get("/config")
def dashboard_config() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    return {
        "projectRoot": str(root),
        "databaseUrl": os.environ.get("NETGUARD_DATABASE_URL") or f"sqlite:///{os.environ.get('NETGUARD_DB_PATH', str(root / 'data' / 'netguard.db'))}",
        "modelDir": str(ensure_models()),
        "openaiConfigured": bool(os.environ.get("NETGUARD_OPENAI_KEY", "").strip()),
        "viteApiProxy": "/api → backend (see vite.config.ts)",
    }


@router.get("/overview")
def overview(session: Session = Depends(get_db)) -> dict[str, Any]:
    init_db()
    snap = get_visibility_service().get_snapshot()
    h = snap.hosts_as_list()
    flows_n = len(snap.flows)
    pkt_n = int(snap.packet_count or 0)
    span = max(1.0, (snap.ended_at or 0) - (snap.started_at or 0))
    pps = int(pkt_n / span) if pkt_n else 0

    sev_rows = session.execute(
        select(MLAlert.severity, func.count()).group_by(MLAlert.severity)
    ).all()
    sev_map = {str(r[0]): int(r[1]) for r in sev_rows}
    crit = sev_map.get("critical", 0)
    high = sev_map.get("high", 0)
    med = sev_map.get("medium", 0)
    low = sev_map.get("low", 0)
    info = sev_map.get("info", 0)

    proto_items = snap.protocol_distribution()
    total_p = max(1, sum(p.get("count", 0) for p in proto_items))
    pie = []
    colors = ["#3b82f6", "#8b5cf6", "#10b981", "#f59e0b", "#06b6d4", "#ec4899", "#ef4444", "#84cc16"]
    for i, p in enumerate(proto_items[:8]):
        c = int(p.get("count", 0))
        pie.append(
            {
                "protocol": p.get("protocol", "?"),
                "count": c,
                "percentage": round(100.0 * c / total_p, 1),
                "color": colors[i % len(colors)],
            }
        )

    atk_rows = session.execute(
        select(MLAlert.attack_type, func.count()).group_by(MLAlert.attack_type)
    ).all()
    atk_colors = ["#ef4444", "#f97316", "#eab308", "#8b5cf6", "#3b82f6", "#06b6d4", "#ec4899"]
    attack_dist: list[dict[str, Any]] = []
    for i, (name, cnt) in enumerate(sorted(atk_rows, key=lambda x: -x[1])[:10]):
        if not name:
            continue
        attack_dist.append(
            {
                "attack": str(name),
                "count": int(cnt),
                "percentage": 0.0,
                "color": atk_colors[i % len(atk_colors)],
                "trend": "—",
            }
        )
    tot_a = sum(a["count"] for a in attack_dist) or 1
    for a in attack_dist:
        a["percentage"] = round(100.0 * a["count"] / tot_a, 1)

    # Timeline: use bandwidth buckets + synthetic alert counts from DB hourly is heavy — use per-alert created hour
    tl: list[dict[str, Any]] = []
    hours = [f"{h:02d}:00" for h in range(0, 24, 2)]
    alert_hours: Counter[int] = Counter()
    for ts in session.scalars(select(MLAlert.created_at)).all():
        if ts is not None:
            alert_hours[int(ts.hour)] += 1
    bw = {b["time"]: b for b in snap.bandwidth_series()}
    for lab in hours:
        hh = int(lab.split(":")[0])
        b = bw.get(lab, {"inbound": 0, "outbound": 0})
        pk = int((b.get("inbound", 0) + b.get("outbound", 0)) * 12000 + 1000)
        tl.append(
            {
                "time": lab,
                "packets": pk,
                "bytes": pk * 1400,
                "alerts": int(alert_hours.get(hh, 0) + alert_hours.get(hh + 1, 0)),
                "anomalies": 0,
            }
        )

    recent = list(
        session.scalars(
            select(MLAlert)
            .where(MLAlert.severity.in_(("critical", "high")))
            .order_by(MLAlert.created_at.desc())
            .limit(6)
        ).all()
    )
    latest_crit = [
        {
            "id": r.id,
            "timestamp": r.created_at.replace(tzinfo=None).isoformat() + "Z" if r.created_at else "",
            "severity": r.severity,
            "title": r.title,
            "description": r.description or "",
            "srcIp": r.src_ip or "",
            "dstIp": r.dst_ip or "",
            "protocol": r.protocol or "",
            "attackType": r.attack_type or "",
            "confidence": float(r.confidence or 0),
            "model": r.model or "",
            "status": r.status,
            "mitre": "—",
            "mitrePhase": "—",
            "features": r.features or {},
            "remediation": [],
            "topShapFeatures": [],
        }
        for r in recent
    ]

    mdir = ensure_models()
    meta = json.loads((mdir / "model_meta.json").read_text(encoding="utf-8"))
    model_type = meta.get("type", "unknown")
    is_real = model_type == "cicids2017_real"
    # Read real accuracy if available; None signals 'pending real training'
    rf_meta = meta.get("rf") or {}
    real_accuracy: float | None = float(rf_meta["accuracy"]) if is_real and "accuracy" in rf_meta else None
    model_block = {
        "modelType": model_type,
        "isRealTraining": is_real,
        "synthetic": not is_real,
        "classes": meta.get("classes", []),
        "nFeatures": meta.get("n_features", 0),
        "rfAccuracy": real_accuracy,
        "xgbAccuracy": float(meta["xgb"]["accuracy"]) if is_real and meta.get("xgb") else None,
    }

    return {
        "source": get_visibility_service().source_label,
        "kpis": {
            "activeHosts": len(h),
            "totalFlows": flows_n,
            "packetsPerSecond": pps,
            "bytesIngestedLabel": f"{round(pkt_n * 1.2 / 1e6, 1)} MB est." if pkt_n else "0 MB",
            "criticalAlerts": crit,
            "highAlerts": high,
            "mediumAlerts": med,
            "lowAlerts": low + info,
            "threatScore": _threat_score(crit, high, med),
            "modelAccuracy": real_accuracy,
            "modelType": model_type,
        },
        "protocolDistribution": pie,
        "attackDistribution": attack_dist,
        "trafficTimeline": tl,
        "latestCriticalAlerts": latest_crit,
        "modelMeta": model_block,
    }


@router.get("/stats")
def quick_stats(session: Session = Depends(get_db)) -> dict[str, Any]:
    """Lightweight counts for Settings / header."""
    init_db()
    n_alerts = int(session.scalar(select(func.count()).select_from(MLAlert)) or 0)
    snap = get_visibility_service().get_snapshot()
    return {
        "alertsTotal": int(n_alerts),
        "hosts": len(snap.hosts_as_list()),
        "flows": len(snap.flows),
        "packets": int(snap.packet_count or 0),
        "visibilitySource": get_visibility_service().source_label,
    }
