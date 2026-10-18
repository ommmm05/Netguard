"""
Global feature importance (Phase 3) — sourced from the trained Random Forest model.

Priority:
  1. Real RF feature_importances_ from the loaded model (cicids2017_real or synthetic_fallback).
  2. Values stored in model_meta.json (written at training time).
  3. Hardcoded weights as last resort if no model is loadable (server cold-start race).

The source is always reported in the API response so the dashboard can show the correct label.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("netguard.forensics.feature_importance")


def global_feature_importance() -> list[dict[str, Any]]:
    """
    Return ordered list of {feature, importance, category, source} dicts.

    Attempts to read real importances from the loaded Random Forest model.
    Falls back to values stored in model_meta.json, then to static reference weights.
    """
    from detection.features import FEATURE_ORDER  # avoid circular at module level

    # ── 1. Try to get live feature importances from the loaded RF model ────────
    try:
        from detection.inference import load_models
        rf, _, __, meta = load_models()
        fi = rf.feature_importances_
        model_type = meta.get("type", "unknown")
        source = f"rf.feature_importances_ ({model_type})"
        items = [
            {
                "feature": FEATURE_ORDER[i],
                "importance": round(float(fi[i]), 6),
                "category": _category(FEATURE_ORDER[i]),
                "source": source,
            }
            for i in range(len(FEATURE_ORDER))
        ]
        items.sort(key=lambda r: -float(r["importance"]))
        return items
    except Exception as e:  # noqa: BLE001
        log.debug("Could not load RF importances live: %s", e)

    # ── 2. Try model_meta.json (written at training time) ────────────────────
    try:
        import json
        import os
        from pathlib import Path

        model_dir = Path(
            os.environ.get(
                "NETGUARD_MODEL_DIR",
                str(Path(__file__).resolve().parents[1] / "data" / "models"),
            )
        )
        meta_path = model_dir / "model_meta.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            fi_dict: dict[str, float] = meta.get("feature_importances", {})
            model_type = meta.get("type", "unknown")
            if fi_dict:
                items = [
                    {
                        "feature": feat,
                        "importance": round(float(fi_dict.get(feat, 0.0)), 6),
                        "category": _category(feat),
                        "source": f"model_meta.json ({model_type})",
                    }
                    for feat in FEATURE_ORDER
                ]
                items.sort(key=lambda r: -float(r["importance"]))
                return items
    except Exception as e:  # noqa: BLE001
        log.debug("Could not read model_meta.json importances: %s", e)

    # ── 3. Static reference weights (last resort; clearly labelled) ───────────
    log.warning("Returning static reference feature importance weights (no model loaded yet).")
    _STATIC_WEIGHTS: dict[str, float] = {
        "dst_port": 0.09, "flow_duration": 0.06, "flow_byts_s": 0.11,
        "flow_pkts_s": 0.10, "tot_fwd_pkts": 0.05, "tot_bwd_pkts": 0.05,
        "fwd_pkt_len_mean": 0.07, "bwd_pkt_len_mean": 0.07,
        "syn_flag_count": 0.08, "ack_flag_count": 0.04,
        "pkt_len_mean": 0.06, "pkt_len_std": 0.05, "down_up_ratio": 0.07,
        "src_port": 0.04, "totlen_fwd_pkts": 0.03, "totlen_bwd_pkts": 0.03,
    }
    items = [
        {
            "feature": feat,
            "importance": round(_STATIC_WEIGHTS.get(feat, 0.02), 6),
            "category": _category(feat),
            "source": "static_reference_pending_training",
        }
        for feat in FEATURE_ORDER
    ]
    items.sort(key=lambda r: -float(r["importance"]))
    return items


def _category(name: str) -> str:
    if "port" in name:
        return "Port"
    if "fwd" in name or "bwd" in name:
        return "Directional"
    if "flag" in name:
        return "TCP Flags"
    if "duration" in name or "ratio" in name:
        return "Timing / Shape"
    if "byts" in name or "pkts" in name or "len" in name or "totlen" in name:
        return "Volume / Rate"
    return "Other"
