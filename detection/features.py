"""Map passive `FlowAgg.to_row()` dicts to the numeric feature vector expected by the ML stack.

Features are constructed deterministically from flow statistics.
No random noise is added — the feature vector is a pure function of the observed flow.
Missing fields are zero-filled, matching the CICIDS2017 zero-fill strategy.
"""

from __future__ import annotations

import math
from typing import Any

import numpy as np

from detection.cicids2017 import CICIDS_SUBSET

FEATURE_ORDER = [c for c in CICIDS_SUBSET if c != "label"]


def _proto_flags(protocol: str) -> tuple[int, int]:
    """Return (syn_count, ack_count) proxy flags from protocol label."""
    p = (protocol or "").upper()
    is_tcp = "TCP" in p
    # Heuristic: passive flows cannot see real TCP flag counts.
    # We use 1/1 for TCP (likely SYN+ACK in any established flow) and 0/0 otherwise.
    return (1, 1) if is_tcp else (0, 0)


def flow_dict_to_vector(row: dict[str, Any]) -> np.ndarray:
    """
    Build a 20-dim CICIDS2017-aligned feature vector from a passive flow row.

    All values are derived purely from observed counters (bytes, packets, duration,
    ports, protocol). No random jitter is added. Missing sub-fields are zero-filled
    using the same convention as load_cicids_csv().
    """
    duration = max(float(row.get("duration", 0) or 0.0), 1e-6)
    bts = int(row.get("bytes", 0) or 0)
    pkts = int(row.get("packets", 0) or 0)
    sp = int(row.get("srcPort", 0) or 0)
    dp = int(row.get("dstPort", 0) or 0)

    # Passive flows observe aggregate totals; split heuristically 55/45 fwd/bwd
    tot_fwd = max(1, int(pkts * 0.55))
    tot_bwd = max(0, pkts - tot_fwd)

    # Byte split
    fwd_bytes = int(bts * 0.55)
    bwd_bytes = bts - fwd_bytes

    # Per-packet statistics
    fwd_mean = fwd_bytes / max(1, tot_fwd)
    bwd_mean = bwd_bytes / max(1, tot_bwd) if tot_bwd > 0 else 0.0
    pkt_mean = bts / max(1, pkts)
    # Packet length std dev: approximated from fwd/bwd mean difference
    pkt_std = math.sqrt(max(0.0, (fwd_mean - bwd_mean) ** 2 * 0.25))

    # Rate features
    flow_byts_s = bts / duration
    flow_pkts_s = pkts / duration

    syn_cnt, ack_cnt = _proto_flags(str(row.get("protocol", "")))

    # Down/Up ratio (bwd / fwd byte ratio)
    down_up = (bwd_bytes / max(1, fwd_bytes)) if fwd_bytes > 0 else 0.0

    # Feature vector — must match FEATURE_ORDER exactly
    vec = np.array(
        [
            float(dp),           # dst_port
            float(sp),           # src_port
            float(duration),     # flow_duration  (microseconds in CICIDS; we use seconds — consistent with training)
            float(tot_fwd),      # tot_fwd_pkts
            float(tot_bwd),      # tot_bwd_pkts
            float(fwd_bytes),    # totlen_fwd_pkts
            float(bwd_bytes),    # totlen_bwd_pkts
            float(fwd_mean * 1.2),  # fwd_pkt_len_max (approx: mean × factor)
            float(max(0.0, fwd_mean * 0.3)),  # fwd_pkt_len_min
            float(fwd_mean),     # fwd_pkt_len_mean
            float(bwd_mean * 1.2),  # bwd_pkt_len_max
            float(max(0.0, bwd_mean * 0.3)),  # bwd_pkt_len_min
            float(bwd_mean),     # bwd_pkt_len_mean
            float(flow_byts_s),  # flow_byts_s
            float(flow_pkts_s),  # flow_pkts_s
            float(pkt_mean),     # pkt_len_mean
            float(pkt_std),      # pkt_len_std
            float(syn_cnt),      # syn_flag_count
            float(ack_cnt),      # ack_flag_count
            float(down_up),      # down_up_ratio
        ],
        dtype=np.float32,
    )
    return vec


def data_frame_preprocess_dummy(X: np.ndarray) -> np.ndarray:
    """
    Clean NaN/Inf values and return float32 array.
    A fitted StandardScaler (scaler.joblib) is preferred when available;
    this function is the identity-clean fallback for inference when no scaler is saved.
    """
    return np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
