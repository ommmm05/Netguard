"""
CICIDS2017 preprocessing pipeline.

Provides utilities to:
  1. Load and clean a raw CICIDS2017 CSV (NaN, Inf, label encoding).
  2. Fit a StandardScaler on training data and transform new samples.
  3. Batch-convert NetGuard visibility flow dicts into model-ready arrays.

The pipeline aligns with the compact 20-dim feature subset defined in
``detection.cicids2017.CICIDS_SUBSET``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder

from detection.cicids2017 import CICIDS_SUBSET, CLASS_LABELS
from detection.features import FEATURE_ORDER, flow_dict_to_vector

log = logging.getLogger(__name__)

# ─── CSV column mapping ─────────────────────────────────────────────
# CICIDS2017 CSVs have whitespace-padded headers.  This map normalises
# the most common variants to our internal snake_case names.
_COL_ALIASES: dict[str, str] = {
    " Destination Port":    "dst_port",
    " Source Port":         "src_port",
    " Flow Duration":       "flow_duration",
    " Total Fwd Packets":   "tot_fwd_pkts",
    " Total Backward Packets": "tot_bwd_pkts",
    "Total Length of Fwd Packets":  "totlen_fwd_pkts",
    " Total Length of Bwd Packets": "totlen_bwd_pkts",
    " Fwd Packet Length Max":  "fwd_pkt_len_max",
    " Fwd Packet Length Min":  "fwd_pkt_len_min",
    " Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Bwd Packet Length Max":   "bwd_pkt_len_max",
    " Bwd Packet Length Min":  "bwd_pkt_len_min",
    " Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Flow Bytes/s":  "flow_byts_s",
    " Flow Packets/s": "flow_pkts_s",
    " Average Packet Size": "pkt_len_mean",
    " Packet Length Std":   "pkt_len_std",
    " SYN Flag Count":  "syn_flag_count",
    " ACK Flag Count":  "ack_flag_count",
    " Down/Up Ratio":   "down_up_ratio",
    " Label": "label",
}


# ─── Load raw CSV ───────────────────────────────────────────────────
def load_cicids_csv(
    path: str | Path,
    *,
    max_rows: int | None = None,
    label_col: str = "label",
) -> tuple[pd.DataFrame, pd.Series]:
    """
    Read a CICIDS2017 CSV, normalise column names, clean NaN/Inf values,
    and return (X_df, y_series) where y is integer-encoded.

    Parameters
    ----------
    path : file path to one of the CICIDS2017 CSV files.
    max_rows : cap the number of rows loaded (useful for demos).
    label_col : name of the target column after renaming.

    Returns
    -------
    X : DataFrame with ``FEATURE_ORDER`` columns (no label).
    y : Series of int-encoded labels (see ``CLASS_LABELS``).
    """
    df = pd.read_csv(str(path), nrows=max_rows, low_memory=False)
    # Normalise whitespace-padded column names
    df.columns = df.columns.str.strip()
    rename = {k.strip(): v for k, v in _COL_ALIASES.items()}
    df.rename(columns=rename, inplace=True)

    # Ensure our feature columns exist; fill missing with 0
    for col in CICIDS_SUBSET:
        if col not in df.columns:
            df[col] = 0.0

    # Clean infinities and NaNs
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0.0, inplace=True)

    # Encode labels → integers matching CLASS_LABELS order
    le = LabelEncoder()
    # Map labels to our simplified taxonomy
    label_map = {
        "BENIGN": "Benign",
        "DoS Hulk": "DoS", "DoS GoldenEye": "DoS",
        "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS",
        "DDoS": "DoS",
        "PortScan": "PortScan",
        "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
        "Bot": "BruteForce",
        "Web Attack – Brute Force": "BruteForce",
        "Web Attack – XSS": "BruteForce",
        "Web Attack – Sql Injection": "BruteForce",
        "Infiltration": "BruteForce",
        "Heartbleed": "DoS",
    }
    if label_col in df.columns:
        df[label_col] = df[label_col].map(
            lambda x: label_map.get(str(x).strip(), "Benign")
        )
        le.fit(list(CLASS_LABELS))
        y = pd.Series(le.transform(df[label_col]), name="label")
    else:
        y = pd.Series(np.zeros(len(df), dtype=int), name="label")

    X = df[[c for c in FEATURE_ORDER if c in df.columns]].copy()
    # Ensure float
    for c in X.columns:
        X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0.0)

    log.info("Loaded %d rows × %d features from %s", len(X), X.shape[1], path)
    return X, y


# ─── Preprocessor class ─────────────────────────────────────────────
class CICIDSPreprocessor:
    """
    Scikit-learn–style preprocessor: fit on training data, transform
    new data.  Wraps a ``StandardScaler`` with NaN/Inf clamping.
    """

    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self._fitted = False

    def fit(self, X: np.ndarray | pd.DataFrame) -> "CICIDSPreprocessor":
        arr = np.asarray(X, dtype=np.float32)
        arr = np.nan_to_num(arr, nan=0.0, posinf=1e12, neginf=-1e12)
        self.scaler.fit(arr)
        self._fitted = True
        return self

    def transform(self, X: np.ndarray | pd.DataFrame) -> np.ndarray:
        arr = np.asarray(X, dtype=np.float32)
        arr = np.nan_to_num(arr, nan=0.0, posinf=1e12, neginf=-1e12)
        if self._fitted:
            return self.scaler.transform(arr).astype(np.float32)
        # If not fitted, return cleaned array as-is (demo fallback)
        return arr

    def fit_transform(self, X: np.ndarray | pd.DataFrame) -> np.ndarray:
        self.fit(X)
        return self.transform(X)


# ─── Batch flow conversion ──────────────────────────────────────────
def preprocess_flow_batch(
    flow_rows: list[dict[str, Any]],
    preprocessor: CICIDSPreprocessor | None = None,
) -> np.ndarray:
    """
    Convert a list of NetGuard visibility flow dicts into a 2-D array
    ready for model inference.

    Parameters
    ----------
    flow_rows : list of dicts as returned by ``FlowAgg.to_row()``.
    preprocessor : optional fitted ``CICIDSPreprocessor`` (uses identity
                   scaling if None).

    Returns
    -------
    X : (N, n_features) float32 array.
    """
    if not flow_rows:
        return np.empty((0, len(FEATURE_ORDER)), dtype=np.float32)

    vecs = np.stack([flow_dict_to_vector(r) for r in flow_rows])
    if preprocessor is not None:
        return preprocessor.transform(vecs)
    return np.nan_to_num(vecs, nan=0.0).astype(np.float32)
