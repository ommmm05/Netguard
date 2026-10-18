"""
Optional PyShark / tshark enrichment for deeper L7 protocol dissection.

NetGuard's core pipeline uses Scapy in ``decoder.py`` for all passive
decoding.  This module provides an **optional** path to enrich flow
metadata via Wireshark's tshark binary (through PyShark) when available.

Usage:
    tshark must be installed and on PATH.
    ``pip install pyshark`` (already in requirements.txt).

This is a supporting validation tool — not the main analysis engine.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def is_tshark_available() -> bool:
    """Check whether tshark is installed and reachable on PATH."""
    import shutil
    return shutil.which("tshark") is not None


def enrich_pcap_with_tshark(
    pcap_path: str | Path,
    *,
    max_packets: int = 500,
) -> list[dict[str, Any]]:
    """
    Run tshark on a PCAP file and return enriched L7 metadata.

    Returns a list of dicts with fields:
        frame_number, timestamp, src_ip, dst_ip, protocol,
        info (tshark summary line).

    Falls back to an empty list if PyShark or tshark is unavailable.
    """
    try:
        import pyshark
    except ImportError:
        log.warning("pyshark not installed; skipping tshark enrichment")
        return []

    if not is_tshark_available():
        log.warning("tshark not found on PATH; skipping enrichment")
        return []

    results: list[dict[str, Any]] = []
    try:
        cap = pyshark.FileCapture(
            str(pcap_path),
            keep_packets=False,
        )
        for i, pkt in enumerate(cap):
            if i >= max_packets:
                break
            try:
                results.append({
                    "frame_number": int(getattr(pkt, "number", i)),
                    "timestamp": str(getattr(pkt, "sniff_time", "")),
                    "src_ip": str(getattr(pkt, "source", getattr(pkt.ip, "src", ""))) if hasattr(pkt, "ip") else "",
                    "dst_ip": str(getattr(pkt, "destination", getattr(pkt.ip, "dst", ""))) if hasattr(pkt, "ip") else "",
                    "protocol": str(pkt.highest_layer),
                    "info": str(getattr(pkt, "info", ""))[:200] if hasattr(pkt, "info") else "",
                    "length": int(pkt.length) if hasattr(pkt, "length") else 0,
                })
            except (AttributeError, TypeError):
                continue
        cap.close()
    except Exception as e:  # noqa: BLE001
        log.warning("tshark enrichment failed: %s", e)

    return results
