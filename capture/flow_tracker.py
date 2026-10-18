"""
capture/flow_tracker.py — Bidirectional Flow Tracker & Feature Extractor.

Aggregates raw ParsedPacket objects into canonical 5-tuple network flows, tracks flow
statistics, manages configurable flow expiration, and extracts exact 20-dim CICIDS
feature vectors for ML threat detection.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import numpy as np

from config import FLOW_MAX_FLOWS, FLOW_MAX_PACKETS, FLOW_TIMEOUT_SECONDS
from capture.packet_parser import ParsedPacket

logger = logging.getLogger(__name__)


def make_canonical_flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> tuple[str, str, int, int, str]:
    """
    Generate a canonical bidirectional 5-tuple key so forward and backward packets
    belong to the same flow.
    """
    p = (proto or "").upper()
    ep1 = (src_ip, src_port)
    ep2 = (dst_ip, dst_port)
    if ep1 <= ep2:
        return (src_ip, dst_ip, src_port, dst_port, p)
    else:
        return (dst_ip, src_ip, dst_port, src_port, p)


@dataclass
class FlowState:
    flow_key: tuple[str, str, int, int, str]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_ts: float = field(default_factory=time.time)
    last_ts: float = field(default_factory=time.time)
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    fwd_pkt_lens: list[int] = field(default_factory=list)
    bwd_pkt_lens: list[int] = field(default_factory=list)
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    is_closed: bool = False

    @property
    def total_packets(self) -> int:
        return self.fwd_pkts + self.bwd_pkts

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    def add_packet(self, pkt: ParsedPacket) -> bool:
        """
        Incorporate a new ParsedPacket into this flow state.
        Returns True if the packet closed the flow (FIN/RST observed).
        """
        self.last_ts = pkt.timestamp
        is_fwd = (pkt.src_ip == self.src_ip and pkt.src_port == self.src_port)

        if is_fwd:
            self.fwd_pkts += 1
            self.fwd_bytes += pkt.packet_length
            self.fwd_pkt_lens.append(pkt.packet_length)
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += pkt.packet_length
            self.bwd_pkt_lens.append(pkt.packet_length)

        if pkt.tcp_flags.get("syn"):
            self.syn_count += 1
        if pkt.tcp_flags.get("ack"):
            self.ack_count += 1
        if pkt.tcp_flags.get("fin"):
            self.fin_count += 1
            self.is_closed = True
        if pkt.tcp_flags.get("rst"):
            self.rst_count += 1
            self.is_closed = True

        if self.total_packets >= FLOW_MAX_PACKETS:
            self.is_closed = True

        return self.is_closed

    def to_row(self) -> dict[str, Any]:
        """Convert flow statistics to a dictionary structure."""
        return {
            "flow_id": f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}_{self.protocol}",
            "srcIp": self.src_ip,
            "dstIp": self.dst_ip,
            "srcPort": self.src_port,
            "dstPort": self.dst_port,
            "protocol": self.protocol,
            "packets": self.total_packets,
            "bytes": self.total_bytes,
            "fwd_pkts": self.fwd_pkts,
            "bwd_pkts": self.bwd_pkts,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "duration": self.duration,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
        }

    def to_cicids_vector(self) -> np.ndarray:
        """
        Extract exact 20-dimensional feature vector required by model_meta.json.
        1. dst_port
        2. src_port
        3. flow_duration
        4. tot_fwd_pkts
        5. tot_bwd_pkts
        6. totlen_fwd_pkts
        7. totlen_bwd_pkts
        8. fwd_pkt_len_max
        9. fwd_pkt_len_min
        10. fwd_pkt_len_mean
        11. bwd_pkt_len_max
        12. bwd_pkt_len_min
        13. bwd_pkt_len_mean
        14. flow_byts_s
        15. flow_pkts_s
        16. pkt_len_mean
        17. pkt_len_std
        18. syn_flag_count
        19. ack_flag_count
        20. down_up_ratio
        """
        dur = max(self.duration, 1e-6)

        f_lens = self.fwd_pkt_lens or [0]
        b_lens = self.bwd_pkt_lens or [0]
        all_lens = f_lens + b_lens

        fwd_max = float(max(f_lens))
        fwd_min = float(min(f_lens))
        fwd_mean = float(self.fwd_bytes / max(1, self.fwd_pkts))

        bwd_max = float(max(b_lens)) if self.bwd_pkts > 0 else 0.0
        bwd_min = float(min(b_lens)) if self.bwd_pkts > 0 else 0.0
        bwd_mean = float(self.bwd_bytes / max(1, self.bwd_pkts)) if self.bwd_pkts > 0 else 0.0

        flow_byts_s = float(self.total_bytes / dur)
        flow_pkts_s = float(self.total_packets / dur)

        pkt_mean = float(self.total_bytes / max(1, self.total_packets))

        # Calculate population standard deviation of packet lengths
        if len(all_lens) > 1:
            variance = sum((x - pkt_mean) ** 2 for x in all_lens) / len(all_lens)
            pkt_std = float(math.sqrt(max(0.0, variance)))
        else:
            pkt_std = 0.0

        down_up = float(self.bwd_bytes / max(1, self.fwd_bytes))

        vec = np.array(
            [
                float(self.dst_port),
                float(self.src_port),
                float(dur),
                float(self.fwd_pkts),
                float(self.bwd_pkts),
                float(self.fwd_bytes),
                float(self.bwd_bytes),
                fwd_max,
                fwd_min,
                fwd_mean,
                bwd_max,
                bwd_min,
                bwd_mean,
                flow_byts_s,
                flow_pkts_s,
                pkt_mean,
                pkt_std,
                float(self.syn_count),
                float(self.ack_count),
                down_up,
            ],
            dtype=np.float32,
        )
        return np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)


class FlowTracker:
    """Thread-safe active flow tracker with configurable expiration."""

    def __init__(self, on_flow_complete: Optional[Callable[[FlowState], None]] = None) -> None:
        self._flows: dict[tuple[str, str, int, int, str], FlowState] = {}
        self._on_flow_complete = on_flow_complete
        self._active_count = 0
        self._completed_count = 0

    @property
    def active_flows_count(self) -> int:
        return len(self._flows)

    @property
    def completed_flows_count(self) -> int:
        return self._completed_count

    def process_packet(self, pkt: ParsedPacket) -> Optional[FlowState]:
        """
        Process a single ParsedPacket.
        If the packet completes a flow or causes an expired flow to flush, returns the completed FlowState.
        """
        key = make_canonical_flow_key(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.transport_protocol)
        flow = self._flows.get(key)

        if flow is None:
            # Memory safety: check max active flows limit
            if len(self._flows) >= FLOW_MAX_FLOWS:
                self.purge_expired_flows(force_oldest=True)

            flow = FlowState(
                flow_key=key,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.transport_protocol,
                first_ts=pkt.timestamp,
            )
            self._flows[key] = flow

        is_closed = flow.add_packet(pkt)

        if is_closed:
            del self._flows[key]
            self._completed_count += 1
            if self._on_flow_complete:
                try:
                    self._on_flow_complete(flow)
                except Exception as e:
                    logger.error("Error in on_flow_complete callback: %s", e)
            return flow

        return None

    def purge_expired_flows(self, now: Optional[float] = None, force_oldest: bool = False) -> list[FlowState]:
        """
        Check for flows that have exceeded FLOW_TIMEOUT_SECONDS and flush them.
        Returns list of flushed FlowState objects.
        """
        current_time = now or time.time()
        flushed: list[FlowState] = []
        expired_keys: list[tuple[str, str, int, int, str]] = []

        for key, flow in self._flows.items():
            if (current_time - flow.last_ts) >= FLOW_TIMEOUT_SECONDS:
                expired_keys.append(key)

        if not expired_keys and force_oldest and self._flows:
            # Evict oldest flow to maintain hard memory bounds
            oldest_key = min(self._flows.keys(), key=lambda k: self._flows[k].last_ts)
            expired_keys.append(oldest_key)

        for key in expired_keys:
            flow = self._flows.pop(key, None)
            if flow:
                flow.is_closed = True
                self._completed_count += 1
                flushed.append(flow)
                if self._on_flow_complete:
                    try:
                        self._on_flow_complete(flow)
                    except Exception as e:
                        logger.error("Error in on_flow_complete callback: %s", e)

        return flushed

    def flush_all_flows(self) -> list[FlowState]:
        """Force-complete every active flow (used when live capture stops)."""
        flushed: list[FlowState] = []
        for key in list(self._flows.keys()):
            flow = self._flows.pop(key, None)
            if flow is None:
                continue
            flow.is_closed = True
            self._completed_count += 1
            flushed.append(flow)
            if self._on_flow_complete:
                try:
                    self._on_flow_complete(flow)
                except Exception as e:
                    logger.error("Error in on_flow_complete callback: %s", e)
        return flushed

    def clear(self) -> None:
        self._flows.clear()
        self._active_count = 0
        self._completed_count = 0
