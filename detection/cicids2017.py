"""
CICIDS2017-style feature names (subset) aligned with common flow-statistic columns.
NetGuard maps its passive flow objects onto this vector; missing fields are zero-filled.
Ref: CIC Flow Features (ISCX/CICIDS2017) — 78+ columns; we use a compact 20-dim set for the demo models.
"""

from __future__ import annotations

# Normalized feature order used by the bundled sklearn / XGBoost models
CICIDS_SUBSET = [
    "dst_port",
    "src_port",
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",
    "totlen_bwd_pkts",
    "fwd_pkt_len_max",
    "fwd_pkt_len_min",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_max",
    "bwd_pkt_len_min",
    "bwd_pkt_len_mean",
    "flow_byts_s",
    "flow_pkts_s",
    "pkt_len_mean",
    "pkt_len_std",
    "syn_flag_count",
    "ack_flag_count",
    "down_up_ratio",
    "label",  # training only — stripped at inference
]

CLASS_LABELS = ("Benign", "DoS", "PortScan", "BruteForce")
