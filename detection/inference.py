from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from xgboost import XGBClassifier

from detection.features import data_frame_preprocess_dummy, flow_dict_to_vector, FEATURE_ORDER
from detection.severity import map_scores_to_alert
from detection.trainer import ensure_models

_models: tuple[RandomForestClassifier, XGBClassifier, IsolationForest, dict] | None = None

MODEL_DIR = os.environ.get("NETGUARD_MODEL_DIR", "")


def load_models() -> tuple[RandomForestClassifier, XGBClassifier, IsolationForest, dict]:
    global _models
    if _models is not None:
        return _models
    mdir = ensure_models()
    import json
    from pathlib import Path

    meta = json.loads((Path(mdir) / "model_meta.json").read_text(encoding="utf-8"))
    rf = joblib.load(Path(mdir) / "rf.joblib")
    xgb = joblib.load(Path(mdir) / "xgb.joblib")
    iso = joblib.load(Path(mdir) / "isoforest.joblib")
    _models = (rf, xgb, iso, meta)
    return _models


@dataclass
class DetectionResult:
    alert: bool
    title: str
    attack_type: str
    confidence: float
    severity: str
    model: str
    details: dict[str, Any]


def predict_on_vector(x: np.ndarray) -> DetectionResult:
    rf, xgb, iso, meta = load_models()
    x2 = data_frame_preprocess_dummy(x.reshape(1, -1))
    p_rf = float(np.max(rf.predict_proba(x2)))
    cls_rf = int(np.argmax(rf.predict_proba(x2), axis=1)[0])
    p_xgb = float(np.max(xgb.predict_proba(x2)))
    cls_xgb = int(np.argmax(xgb.predict_proba(x2), axis=1)[0])
    s_if = -float(iso.decision_function(x2)[0])
    p_if = 1.0 / (1.0 + np.exp(-s_if))  # sigmoid
    conf = float((p_rf + p_xgb) / 2.0)
    if cls_rf == cls_xgb:
        cls = cls_rf
    else:
        cls = cls_rf if p_rf >= p_xgb else cls_xgb
    classes: list[str] = list(meta.get("classes", []))
    label = classes[min(cls, len(classes) - 1)]
    is_anom = p_if > 0.6
    attack_type = "Anomaly" if is_anom and label == "Benign" else label
    title = f"ML: {attack_type} (ensemble)"
    sev, fire = map_scores_to_alert(conf, label, p_if, cls_rf != cls_xgb)
    is_attacky = (label != "Benign" or is_anom)
    return DetectionResult(
        alert=bool(fire and is_attacky),
        title=title,
        attack_type=attack_type,
        confidence=round(conf * 100.0, 2),
        severity=sev,
        model="RF + XGBoost + IsolationForest",
        details={
            "proba_rf": round(p_rf, 4),
            "proba_xgb": round(p_xgb, 4),
            "if_score_sigmoid": round(float(p_if), 4),
            "rf_class": cls_rf,
            "xgb_class": cls_xgb,
        },
    )


def run_detection_on_flows(
    flow_rows: list[dict[str, Any]], min_conf: float = 0.45
) -> list[tuple[dict[str, Any], DetectionResult]]:
    out: list[tuple[dict[str, Any], DetectionResult]] = []
    for r in flow_rows:
        v = flow_dict_to_vector(r)
        d = predict_on_vector(v)
        if d.confidence / 100.0 >= min_conf and d.alert:
            out.append((r, d))
    return out


def make_alert_id() -> str:
    return f"ALT-{uuid.uuid4().hex[:8].upper()}"
