"""
detection/adapter.py — Transparent Model Adapter for Existing Detection Engine.

Connects flow tracking telemetry to the existing Random Forest + XGBoost + Isolation Forest
ensemble model without altering existing model behavior or retraining.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import numpy as np

from capture.flow_tracker import FlowState
from detection.inference import DetectionResult, predict_on_vector, make_alert_id

logger = logging.getLogger(__name__)


def evaluate_flow_state(flow: FlowState) -> tuple[dict[str, Any], DetectionResult]:
    """
    Evaluate a completed/expired FlowState through the existing ML detection engine.
    Returns (flow_row_dict, DetectionResult).
    """
    vector = flow.to_cicids_vector()
    result = predict_on_vector(vector)
    return flow.to_row(), result


def format_transparent_ensemble_details(d: DetectionResult) -> dict[str, Any]:
    """
    Format transparent ensemble diagnostic details for SOC dashboard & API callers.
    """
    det = d.details or {}
    return {
        "rfPredictionClass": det.get("rf_class"),
        "rfProbability": det.get("proba_rf"),
        "xgbPredictionClass": det.get("xgb_class"),
        "xgbProbability": det.get("proba_xgb"),
        "isoForestSigmoidScore": det.get("if_score_sigmoid"),
        "ensembleDecision": d.attack_type,
        "confidencePercent": d.confidence,
        "severity": d.severity,
        "alertTriggered": d.alert,
        "modelEnsembleName": d.model,
    }
