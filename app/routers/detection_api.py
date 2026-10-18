"""ML detection (Phase 2) — train artifacts, run inference, list persisted alerts.

Endpoints:
  GET  /detection/status            — model status + meta
  GET  /detection/model-metrics     — real evaluation metrics from trained model
  GET  /detection/train-status      — background training progress
  POST /detection/scan              — run detection on current visibility flows
  GET  /detection/inference-preview — per-flow ensemble scores (no DB write)
  GET  /detection/alerts            — list persisted ML alerts
  POST /detection/upload-cicids     — upload CICIDS2017 CSV and trigger real training
"""

from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.database_deps import get_db
from database.models import MLAlert
from database.session import init_db
from detection.inference import make_alert_id, predict_on_vector, run_detection_on_flows
from detection.features import flow_dict_to_vector
from detection.trainer import (
    ensure_models,
    get_train_status,
    train_on_cicids_csv_background,
)
from visibility.service import get_visibility_service

router = APIRouter(prefix="/detection", tags=["detection"])

# Upload dir for CICIDS CSVs
_CSV_DIR = Path(__file__).resolve().parents[2] / "data" / "cicids_uploads"
_CSV_DIR.mkdir(parents=True, exist_ok=True)


# ─── Status + meta ────────────────────────────────────────────────────────────
@router.get("/status")
def status() -> dict:
    mdir = ensure_models()
    meta = json.loads((mdir / "model_meta.json").read_text(encoding="utf-8"))
    return {"ok": True, "modelDir": str(mdir), "meta": meta}


# ─── Real model metrics ───────────────────────────────────────────────────────
@router.get("/model-metrics")
def model_metrics() -> dict:
    """
    Return evaluation metrics from the trained model.
    If type='synthetic_fallback', the metrics are clearly labelled as not meaningful.
    If type='cicids2017_real', the metrics are from a real train/test split on CICIDS data.
    """
    mdir = ensure_models()
    meta_path = mdir / "model_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    model_type = meta.get("type", "unknown")
    is_real = model_type == "cicids2017_real"

    return {
        "ok": True,
        "modelType": model_type,
        "isRealTraining": is_real,
        "warning": None if is_real else (
            "Models trained on synthetic random data — metrics are NOT meaningful. "
            "Upload a real CICIDS2017 CSV via POST /api/detection/upload-cicids to get real results."
        ),
        "rf": meta.get("rf"),
        "xgb": meta.get("xgb"),
        "classes": meta.get("classes", []),
        "nFeatures": meta.get("n_features", 0),
        "featureImportances": meta.get("feature_importances", {}),
        "trainInfo": {
            "csvSource": meta.get("csv_source"),
            "nTrain": meta.get("n_train"),
            "nTest": meta.get("n_test"),
        },
    }


# ─── Background training status ───────────────────────────────────────────────
@router.get("/train-status")
def train_status() -> dict:
    """Poll background CICIDS training progress."""
    return {"ok": True, **get_train_status()}


# ─── CICIDS CSV upload + trigger real training ────────────────────────────────
@router.post("/upload-cicids")
async def upload_cicids(file: UploadFile = File(...)) -> dict:
    """
    Accept a CICIDS2017-format CSV file, save it, and start background training.
    The real model will replace the current model_meta.json + joblib artifacts.
    Poll GET /detection/train-status for progress.
    """
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(400, "File must be a .csv")
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "Empty file")
    if len(raw) < 1024:
        raise HTTPException(400, "File too small to be a valid CICIDS CSV")

    name = f"{uuid.uuid4().hex}_{(file.filename or 'cicids.csv').replace('/', '_')}"
    dest = _CSV_DIR / name
    dest.write_bytes(raw)

    # Invalidate existing model cache so training starts fresh
    from detection import inference as inf  # noqa: PLC0415
    inf._models = None

    train_on_cicids_csv_background(dest)
    return {
        "ok": True,
        "message": "CICIDS2017 training started in background. Poll GET /api/detection/train-status.",
        "savedAs": str(dest),
        "sizeBytes": len(raw),
    }


# ─── Detection scan ───────────────────────────────────────────────────────────
class ScanBody(BaseModel):
    min_confidence: float = Field(0.4, ge=0.0, le=1.0)
    clear_existing: bool = Field(False, description="Delete all ml_alerts first (use carefully)")


def execute_detection_scan(session: Session, body: ScanBody) -> dict:
    init_db()
    snap = get_visibility_service().get_snapshot()
    rows: list[dict[str, Any]] = []
    for f in snap.flows.values():
        r = f.to_row()
        if r.get("bytes", 0) and r.get("packets", 0):
            rows.append(r)
    if not rows:
        return {"created": 0, "evaluated": 0, "candidates": 0,
                "message": "No flows available — ingest a PCAP or start live capture first."}

    if body.clear_existing:
        session.execute(delete(MLAlert))
        session.flush()

    det = run_detection_on_flows(rows, min_conf=body.min_confidence)
    created = 0
    for flow, d in det[:200]:
        if not d.alert:
            continue
        aid = make_alert_id()
        feat = {
            "dst_port": flow.get("dstPort"),
            "flow_duration": flow.get("duration"),
            "byte_count": flow.get("bytes"),
            **d.details,
        }
        a = MLAlert(
            id=aid,
            created_at=datetime.utcnow(),
            severity=d.severity,
            title=d.title,
            description=f"Passive flow {flow.get('srcIp')} → {flow.get('dstIp')} :{flow.get('dstPort')}",
            src_ip=flow.get("srcIp"),
            dst_ip=flow.get("dstIp"),
            protocol=str(flow.get("protocol", "")),
            attack_type=d.attack_type,
            confidence=d.confidence,
            model=d.model,
            status="open",
            features=feat,
            shap_top=None,
            flow_id=str(flow.get("flow_id", ""))[:120],
        )
        session.add(a)
        created += 1
    return {"created": created, "evaluated": len(rows), "candidates": len(det)}


@router.post("/scan")
def run_scan(body: ScanBody, session: Session = Depends(get_db)) -> dict:
    return execute_detection_scan(session, body)


# ─── Live inference preview ───────────────────────────────────────────────────
@router.get("/inference-preview")
def inference_preview(limit: int = 20) -> dict:
    """Last N flows with ensemble scores (no DB writes) — powers Detection Live Inference tab."""
    init_db()
    snap = get_visibility_service().get_snapshot()
    rows = [f.to_row() for f in snap.flows.values()]
    rows.sort(key=lambda r: (r.get("bytes") or 0), reverse=True)
    out: list[dict[str, Any]] = []
    for r in rows[: max(1, min(limit, 100))]:
        try:
            v = flow_dict_to_vector(r)
            d = predict_on_vector(v)
        except Exception as e:  # noqa: BLE001
            out.append({
                "time": (r.get("endTime") or "")[:19].replace("T", " "),
                "srcIp": r.get("srcIp"),
                "dstIp": r.get("dstIp"),
                "proto": r.get("protocol"),
                "prediction": "error",
                "confidence": 0,
                "model": str(e),
                "latency": "—",
                "severity": "info",
            })
            continue
        out.append({
            "time": (r.get("endTime") or "")[:19].replace("T", " "),
            "srcIp": r.get("srcIp"),
            "dstIp": r.get("dstIp"),
            "proto": r.get("protocol"),
            "prediction": d.attack_type,
            "confidence": d.confidence,
            "model": d.model,
            "latency": "< 5ms",
            "severity": d.severity,
        })
    return {"rows": out, "source": get_visibility_service().source_label}


# ─── Alert listing ────────────────────────────────────────────────────────────
@router.get("/alerts")
def list_alerts(limit: int = 200, session: Session = Depends(get_db)) -> dict:
    init_db()
    q = select(MLAlert).order_by(MLAlert.created_at.desc()).limit(max(1, min(limit, 2000)))
    rows = list(session.execute(q).scalars().all())
    out = [
        {
            "id": r.id,
            "timestamp": r.created_at.replace(tzinfo=None).isoformat() + "Z" if r.created_at else None,
            "severity": r.severity,
            "title": r.title,
            "description": r.description,
            "srcIp": r.src_ip,
            "dstIp": r.dst_ip,
            "protocol": r.protocol,
            "attackType": r.attack_type,
            "confidence": r.confidence,
            "model": r.model,
            "status": r.status,
            "features": r.features,
            "flowId": r.flow_id,
        }
        for r in rows
    ]
    return {"alerts": out}
