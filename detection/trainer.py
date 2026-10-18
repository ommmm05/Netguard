"""
Model training for NetGuard detection pipeline.

Priority:
  1. Real CICIDS2017 training  — triggered by POST /api/detection/train or env NETGUARD_CICIDS_CSV
  2. Synthetic fallback         — used ONLY when no CSV is available; clearly labelled in model_meta.json

The two paths are explicitly separated.  The synthetic path is never silently promoted
as a production model; it always writes  type="synthetic_fallback"  into model_meta.json.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from detection.cicids2017 import CLASS_LABELS
from detection.features import FEATURE_ORDER, data_frame_preprocess_dummy

log = logging.getLogger("netguard.trainer")

N_FEATURES = len(FEATURE_ORDER)

# ─── Training state (non-blocking background tracking) ────────────────────────
_train_lock = threading.Lock()
_train_status: dict[str, Any] = {"state": "idle", "message": "", "progress": 0}


def get_train_status() -> dict[str, Any]:
    with _train_lock:
        return dict(_train_status)


def _set_status(state: str, msg: str, progress: int = 0) -> None:
    with _train_lock:
        _train_status.update({"state": state, "message": msg, "progress": progress})


# ─── Model directory ──────────────────────────────────────────────────────────
def _model_dir(env_var: str = "NETGUARD_MODEL_DIR") -> Path:
    return Path(
        os.environ.get(env_var, str(Path(__file__).resolve().parents[1] / "data" / "models"))
    )


# ─── Synthetic fallback (emergency only — clearly labelled) ───────────────────
def _synthetic_xy_fallback(seed: int = 42, n: int = 4000) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate random synthetic training data as an emergency fallback.
    NOT representative of real network traffic.
    The resulting model is labelled type='synthetic_fallback' in model_meta.json.
    """
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, N_FEATURES)).astype(np.float32)
    score = (X[:, 0] * 0.2 + X[:, 2] * 0.1 + (X[:, 8] - X[:, 12]) * 0.4 + X[:, 15] * 0.2)
    y = np.zeros(n, dtype=int)
    y[score > 0.3] = 1
    y[score < -0.45] = 2
    y[score * score > 0.25] = 3
    y[(X[:, 0] > 1.0) & (X[:, 3] > 0.0)] = 0
    return X, y


def _fit_and_save(
    X_tr: np.ndarray,
    X_te: np.ndarray,
    y_tr: np.ndarray,
    y_te: np.ndarray,
    out_dir: Path,
    model_type: str,
    extra_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fit RF + XGBoost + IsoForest, evaluate, save, write model_meta.json."""
    _set_status("training", "Fitting Random Forest…", 20)
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=20, n_jobs=-1, random_state=42, class_weight="balanced"
    )
    rf.fit(X_tr, y_tr)

    _set_status("training", "Fitting XGBoost…", 50)
    xgb = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.9,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
        eval_metric="mlogloss",
    )
    xgb.fit(X_tr, y_tr)

    _set_status("training", "Fitting Isolation Forest…", 75)
    iso = IsolationForest(n_estimators=200, contamination=0.1, random_state=42, n_jobs=-1)
    iso.fit(np.vstack([X_tr, X_te]))

    _set_status("training", "Evaluating…", 85)

    y_pred_rf = rf.predict(X_te)
    y_pred_xgb = xgb.predict(X_te)

    classes = list(CLASS_LABELS)
    labels_present = sorted(set(y_te.tolist()) | set(y_pred_rf.tolist()))

    def _metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, Any]:
        acc = float(accuracy_score(y_true, y_pred))
        prec = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
        rec = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
        f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
        # Per-class report
        report = classification_report(
            y_true, y_pred,
            labels=labels_present,
            target_names=[classes[i] for i in labels_present if i < len(classes)],
            output_dict=True, zero_division=0
        )
        return {"accuracy": round(acc * 100, 2), "precision": round(prec * 100, 2),
                "recall": round(rec * 100, 2), "f1": round(f1 * 100, 2), "report": report}

    rf_metrics = _metrics(y_te, y_pred_rf)
    xgb_metrics = _metrics(y_te, y_pred_xgb)

    # Real RF feature importances
    fi = rf.feature_importances_.tolist()

    _set_status("training", "Saving models…", 92)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(rf, out_dir / "rf.joblib")
    joblib.dump(xgb, out_dir / "xgb.joblib")
    joblib.dump(iso, out_dir / "isoforest.joblib")

    meta: dict[str, Any] = {
        "type": model_type,
        "n_features": N_FEATURES,
        "feature_order": FEATURE_ORDER,
        "classes": classes,
        "rf": rf_metrics,
        "xgb": xgb_metrics,
        "feature_importances": {FEATURE_ORDER[i]: round(fi[i], 6) for i in range(len(FEATURE_ORDER))},
        **(extra_meta or {}),
    }
    (out_dir / "model_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    _set_status("done", f"Training complete. RF accuracy: {rf_metrics['accuracy']}%", 100)
    log.info("Models saved to %s (type=%s, rf_acc=%.1f%%)", out_dir, model_type, rf_metrics["accuracy"])
    return meta


# ─── CICIDS2017 real training ─────────────────────────────────────────────────
def train_on_cicids_csv(csv_path: str | Path, out_dir: Path | None = None) -> dict[str, Any]:
    """
    Train RF + XGBoost + IsoForest on a real CICIDS2017 CSV file.
    The CSV must contain columns matching CICIDS2017 naming (whitespace-padded is OK).

    Returns the model_meta dict with real evaluation metrics.
    """
    from detection.preprocessing import load_cicids_csv, CICIDSPreprocessor  # local import to avoid circular

    out_dir = out_dir or _model_dir()
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"CICIDS CSV not found: {csv_path}")

    _set_status("training", f"Loading CICIDS2017 CSV: {csv_path.name}…", 5)
    log.info("Loading CICIDS CSV: %s", csv_path)

    X_df, y = load_cicids_csv(csv_path)
    X_arr = X_df.values.astype(np.float32)

    _set_status("training", "Fitting StandardScaler…", 12)
    prep = CICIDSPreprocessor()
    X_scaled = prep.fit_transform(X_arr)

    # Save scaler for inference use
    joblib.dump(prep, out_dir / "scaler.joblib")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X_scaled, y.values, test_size=0.2, random_state=42, stratify=y
    )

    n_classes = len(set(y_te.tolist()))
    log.info("Training set: %d rows, %d features, %d classes", len(X_tr), X_arr.shape[1], n_classes)

    return _fit_and_save(
        X_tr, X_te, y_tr, y_te, out_dir,
        model_type="cicids2017_real",
        extra_meta={"csv_source": str(csv_path), "n_train": len(X_tr), "n_test": len(X_te)},
    )


def train_on_cicids_csv_background(csv_path: str | Path, out_dir: Path | None = None) -> None:
    """Non-blocking: run CICIDS training in a background thread."""
    def _run():
        try:
            train_on_cicids_csv(csv_path, out_dir)
            # Invalidate in-memory model cache so next inference loads fresh models
            from detection import inference as inf  # noqa: PLC0415
            inf._models = None
        except Exception as e:  # noqa: BLE001
            _set_status("error", str(e), 0)
            log.error("CICIDS training failed: %s", e)

    _set_status("starting", "Starting CICIDS2017 training thread…", 0)
    t = threading.Thread(target=_run, daemon=True)
    t.start()


# ─── Ensure models exist (startup check) ─────────────────────────────────────
def ensure_models(out_dir: Path | None = None, env_var: str = "NETGUARD_MODEL_DIR") -> Path:
    """
    Return model dir.  If models are missing:
      - If NETGUARD_CICIDS_CSV is set and the file exists → train on real data.
      - Otherwise → train synthetic fallback (clearly labelled, warns loudly).
    """
    out_dir = out_dir or _model_dir(env_var)
    out_dir.mkdir(parents=True, exist_ok=True)

    rf_p = out_dir / "rf.joblib"
    xgb_p = out_dir / "xgb.joblib"
    ifp = out_dir / "isoforest.joblib"
    meta_path = out_dir / "model_meta.json"

    if rf_p.is_file() and xgb_p.is_file() and ifp.is_file() and meta_path.is_file():
        return out_dir  # Models already exist — nothing to do

    # ── Check for real CICIDS CSV ────────────────────────────────────────────
    cicids_csv = os.environ.get("NETGUARD_CICIDS_CSV", "").strip()
    if cicids_csv and Path(cicids_csv).exists():
        log.info("NETGUARD_CICIDS_CSV found — training real CICIDS2017 model on startup")
        try:
            train_on_cicids_csv(cicids_csv, out_dir)
            return out_dir
        except Exception as e:  # noqa: BLE001
            log.warning("Real CICIDS training failed (%s) — falling back to synthetic", e)
    else:
        if cicids_csv:
            log.warning(
                "NETGUARD_CICIDS_CSV=%s does not exist — synthetic fallback will be used. "
                "Place a real CICIDS2017 CSV there and restart to get a real model.",
                cicids_csv,
            )
        else:
            log.warning(
                "No CICIDS2017 CSV available (set NETGUARD_CICIDS_CSV=<path>). "
                "Using synthetic fallback model — NOT suitable for production evaluation."
            )

    # ── Synthetic fallback ────────────────────────────────────────────────────
    log.warning("Building synthetic_fallback model — accuracy metrics are NOT meaningful.")
    X, y = _synthetic_xy_fallback()
    X = data_frame_preprocess_dummy(X)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    _fit_and_save(
        X_tr, X_te, y_tr, y_te, out_dir,
        model_type="synthetic_fallback",
    )
    return out_dir
