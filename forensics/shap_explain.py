"""SHAP tree explanations for the RandomForest detector."""

from __future__ import annotations

from typing import Any

import numpy as np
import shap
from sklearn.ensemble import RandomForestClassifier

from detection.features import FEATURE_ORDER, data_frame_preprocess_dummy
from detection.inference import load_models


def vector_from_features(feat: dict[str, Any] | None) -> np.ndarray:
    v = np.zeros((1, len(FEATURE_ORDER)), dtype=np.float32)
    if not feat:
        return v
    # align common keys
    for i, name in enumerate(FEATURE_ORDER):
        if name in feat and feat[name] is not None:
            try:
                v[0, i] = float(feat[name])
            except (TypeError, ValueError):
                pass
    if "flow_duration" not in feat and feat.get("byte_count"):
        v[0, 2] = float(feat.get("flow_duration", 0) or 0.0001)
    return data_frame_preprocess_dummy(v)


def shap_explain_for_row(feat: dict[str, Any] | None) -> dict[str, Any]:
    """Return top contributions + waterfall data for the RF model."""
    rf, _, __, _meta = load_models()
    x = vector_from_features(feat)
    expl = shap.TreeExplainer(rf)
    shap_values = expl.shap_values(x)
    p = rf.predict_proba(x)[0]
    c = int(np.argmax(p))
    ev = expl.expected_value
    if isinstance(shap_values, list):
        sv = np.ravel(np.asarray(shap_values[c][0], dtype=np.float32))
        base = float(np.asarray(ev).reshape(-1)[c]) if ev is not None else 0.0
    else:
        sv = np.ravel(np.asarray(shap_values[0], dtype=np.float32))
        base = float(np.asarray(ev).reshape(-1)[0]) if ev is not None else 0.0
    pairs = sorted(
        [
            {
                "feature": FEATURE_ORDER[i],
                "value": float(x[0, i]),
                "shap": float(sv[i]) if i < len(sv) else 0.0,
            }
            for i in range(len(FEATURE_ORDER))
        ],
        key=lambda d: abs(d["shap"]),
        reverse=True,
    )[:12]
    return {
        "baseValue": base,
        "classIndex": c,
        "proba": [float(x) for x in p.tolist()],
        "top": pairs,
        "waterfall": {
            "base": base,
            "rows": pairs,
            "out": float(base + float(np.sum(np.ravel(sv)))),
        },
    }
