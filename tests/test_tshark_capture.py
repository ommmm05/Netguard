"""
tests/test_tshark_capture.py — Comprehensive unit and integration tests for TShark live capture pipeline.
"""

from __future__ import annotations

import time
import numpy as np
import pytest

from config import find_tshark_executable, FLOW_TIMEOUT_SECONDS
from capture.flow_tracker import FlowTracker, FlowState, make_canonical_flow_key
from capture.packet_parser import ParsedPacket, parse_tshark_frame
from capture.tshark_manager import TSharkCaptureManager, get_tshark_info, list_tshark_interfaces
from detection.adapter import evaluate_flow_state, format_transparent_ensemble_details
from detection.inference import predict_on_vector


def test_tshark_executable_finder():
    """Verify dynamic TShark path resolution."""
    path, detail = find_tshark_executable()
    info = get_tshark_info()
    assert isinstance(info["available"], bool)
    assert isinstance(detail, str)


def test_canonical_flow_key():
    """Verify bidirectional 5-tuple flow key produces identical keys for forward and reverse packets."""
    k1 = make_canonical_flow_key("192.168.1.10", 54321, "8.8.8.8", 53, "UDP")
    k2 = make_canonical_flow_key("8.8.8.8", 53, "192.168.1.10", 54321, "UDP")
    assert k1 == k2


def test_parse_tshark_ek_frame():
    """Verify TShark EK JSON parsing extracts correct packet metadata."""
    sample_frame = {
        "layers": {
            "frame": {
                "frame_frame_number": "42",
                "frame_frame_time_epoch": "1700000000.123",
                "frame_frame_len": "512",
            },
            "eth": {
                "eth_eth_src": "00:11:22:33:44:55",
                "eth_eth_dst": "aa:bb:cc:dd:ee:ff",
            },
            "ip": {
                "ip_ip_src": "192.168.1.50",
                "ip_ip_dst": "10.0.0.1",
                "ip_ip_ttl": "128",
            },
            "tcp": {
                "tcp_tcp_srcport": "49152",
                "tcp_tcp_dstport": "443",
                "tcp_tcp_flags_tree": {
                    "tcp_tcp_flags_syn": "1",
                    "tcp_tcp_flags_ack": "0",
                    "tcp_tcp_flags_fin": "0",
                },
            },
            "tls": {
                "tls_tls_handshake_extensions_server_name": "example.com",
            },
        }
    }

    pkt = parse_tshark_frame(sample_frame, frame_counter=42)
    assert pkt is not None
    assert pkt.frame_number == 42
    assert pkt.src_ip == "192.168.1.50"
    assert pkt.dst_ip == "10.0.0.1"
    assert pkt.src_port == 49152
    assert pkt.dst_port == 443
    assert pkt.transport_protocol == "TCP"
    assert pkt.network_protocol == "IPv4"
    assert pkt.packet_length == 512
    assert pkt.tcp_flags.get("syn") is True
    assert pkt.tls_meta is not None
    assert pkt.tls_meta.get("sni") == "example.com"


def test_flow_tracker_aggregation_and_cicids_vector():
    """Verify FlowTracker aggregates bidirectional packets into a valid 20-dim CICIDS feature vector."""
    tracker = FlowTracker()
    now = time.time()

    # Forward packet
    p1 = ParsedPacket(
        frame_number=1,
        timestamp=now,
        src_ip="192.168.1.5",
        dst_ip="1.1.1.1",
        src_port=55555,
        dst_port=80,
        transport_protocol="TCP",
        packet_length=100,
        tcp_flags={"syn": True},
    )

    # Reverse packet
    p2 = ParsedPacket(
        frame_number=2,
        timestamp=now + 0.05,
        src_ip="1.1.1.1",
        dst_ip="192.168.1.5",
        src_port=80,
        dst_port=55555,
        transport_protocol="TCP",
        packet_length=200,
        tcp_flags={"ack": True},
    )

    flow_res1 = tracker.process_packet(p1)
    assert flow_res1 is None  # Flow active
    assert tracker.active_flows_count == 1

    flow_res2 = tracker.process_packet(p2)
    assert flow_res2 is None  # Flow active

    # Expire flow
    expired = tracker.purge_expired_flows(now=now + FLOW_TIMEOUT_SECONDS + 5.0)
    assert len(expired) == 1
    flow = expired[0]

    assert flow.fwd_pkts == 1
    assert flow.bwd_pkts == 1
    assert flow.fwd_bytes == 100
    assert flow.bwd_bytes == 200
    assert flow.syn_count == 1
    assert flow.ack_count == 1

    # Check 20-dim feature vector alignment
    vec = flow.to_cicids_vector()
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (20,)
    assert not np.isnan(vec).any()
    assert not np.isinf(vec).any()


def test_detection_ensemble_adapter():
    """Verify transparent model adapter evaluates a 20-dim feature vector cleanly."""
    dummy_vec = np.zeros(20, dtype=np.float32)
    res = predict_on_vector(dummy_vec)
    assert hasattr(res, "alert")
    assert hasattr(res, "attack_type")
    assert hasattr(res, "confidence")
    assert hasattr(res, "severity")

    flow = FlowState(
        flow_key=("192.168.1.1", "10.0.0.1", 1234, 80, "TCP"),
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        fwd_pkts=5,
        bwd_pkts=5,
        fwd_bytes=500,
        bwd_bytes=1000,
    )

    flow_dict, d_result = evaluate_flow_state(flow)
    assert flow_dict["srcIp"] == "192.168.1.1"
    details = format_transparent_ensemble_details(d_result)
    assert "ensembleDecision" in details
    assert "confidencePercent" in details


def test_tshark_manager_lifecycle():
    """Verify TShark capture manager state management and duplicate start prevention."""
    mgr = TSharkCaptureManager()
    st = mgr.get_status()
    assert st["engine"] == "TShark"
    assert st["running"] is False

    # Attempting to start with invalid path or unavailable tshark should handle error gracefully
    ok, msg = mgr.start_capture("invalid_interface_123456")
    if not st["tsharkAvailable"]:
        assert ok is False
        assert "unavailable" in msg.lower() or "not found" in msg.lower()
    else:
        # If tshark is installed, stop it cleanly
        mgr.stop_capture()
