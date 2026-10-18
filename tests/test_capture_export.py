"""
tests/test_capture_export.py — Unit and integration tests for NetGuard capture export,
session tracking, PCAPNG download, CSV export, and security boundaries.
"""

from __future__ import annotations

import os
import pytest
from starlette.testclient import TestClient

from app.main import app
from capture.tshark_manager import TSharkCaptureManager, get_capture_manager, CAPTURES_DIR


@pytest.fixture
def client():
    return TestClient(app)


def test_capture_sessions_persistence():
    """Verify session metadata recording, retrieval, and disk persistence."""
    mgr = TSharkCaptureManager()
    
    # Check that initial session list is a list
    sessions = mgr.get_capture_sessions()
    assert isinstance(sessions, list)
    
    # Record a test session
    session_id = "test_export_session_123"
    dummy_filepath = os.path.join(CAPTURES_DIR, f"{session_id}.pcapng")
    with open(dummy_filepath, "wb") as f:
        # Standard pcapng Section Header Block (SHB) magic bytes: 0x0A0D0D0A
        f.write(b"\x0a\x0d\x0d\x0a\x00\x00\x00\x1c\x1a\x2b\x3c\x4d")
        f.write(b"\x00" * 16)
        
    try:
        mgr._record_session({
            "id": session_id,
            "filename": f"{session_id}.pcapng",
            "filepath": dummy_filepath,
            "interface": "Wi-Fi",
            "bpfFilter": "tcp port 80",
            "startTime": "2026-09-10T00:00:00Z",
            "endTime": "2026-09-10T00:01:00Z",
            "durationSeconds": 60.0,
            "packetCount": 42,
            "status": "completed",
        })
        
        # Verify retrieval via manager
        sess = mgr.get_capture_session(session_id)
        assert sess is not None
        assert sess["id"] == session_id
        assert sess["packetCount"] == 42
        assert sess["interface"] == "Wi-Fi"
        assert sess["bpfFilter"] == "tcp port 80"
        assert sess["fileSizeBytes"] >= 28
        assert "fileSize" in sess
        
        # Verify index reloads from disk
        mgr2 = TSharkCaptureManager()
        sess_reloaded = mgr2.get_capture_session(session_id)
        assert sess_reloaded is not None
        assert sess_reloaded["id"] == session_id
        
        # Verify delete
        deleted = mgr.delete_capture_session(session_id)
        assert deleted is True
        assert mgr.get_capture_session(session_id) is None
        assert not os.path.exists(dummy_filepath)
    finally:
        if os.path.exists(dummy_filepath):
            os.remove(dummy_filepath)


def test_api_capture_sessions_endpoints(client: TestClient):
    """Verify /api/capture/sessions endpoints."""
    # List sessions
    res = client.get("/api/capture/sessions")
    assert res.status_code == 200
    data = res.json()
    assert "sessions" in data
    assert "total" in data


def test_api_capture_download_and_security(client: TestClient):
    """Verify download endpoint, pcapng headers, and path traversal security."""
    mgr = get_capture_manager()
    session_id = "test_download_security_456"
    filepath = os.path.join(CAPTURES_DIR, f"{session_id}.pcapng")
    
    # Write genuine pcapng SHB block
    with open(filepath, "wb") as f:
        f.write(b"\x0a\x0d\x0d\x0a\x00\x00\x00\x1c\x1a\x2b\x3c\x4d")
        f.write(b"\x00" * 16)
        
    mgr._record_session({
        "id": session_id,
        "filename": f"{session_id}.pcapng",
        "filepath": filepath,
        "interface": "Wi-Fi",
        "bpfFilter": "",
        "startTime": "2026-09-10T00:00:00Z",
        "endTime": "2026-09-10T00:00:10Z",
        "durationSeconds": 10.0,
        "packetCount": 10,
        "status": "completed",
    })
    
    try:
        # Download valid session
        dl_res = client.get(f"/api/capture/sessions/{session_id}/download")
        assert dl_res.status_code == 200
        assert dl_res.headers.get("content-type") == "application/vnd.tcpdump.pcap"
        assert f"{session_id}.pcapng" in dl_res.headers.get("content-disposition", "")
        assert dl_res.content.startswith(b"\x0a\x0d\x0d\x0a")  # PCAPNG magic header
        
        # Test path traversal attack prevention
        attack_ids = [
            "../../etc/passwd",
            "..%2F..%2Fwindows%2Fsystem32",
            "test/../../../boot.ini",
            "invalid*char?id",
        ]
        for aid in attack_ids:
            bad_res = client.get(f"/api/capture/sessions/{aid}/download")
            assert bad_res.status_code in (400, 404), f"Failed to reject traversal: {aid}"
            
        # Test non-existent session
        nf_res = client.get("/api/capture/sessions/non_existent_id_999/download")
        assert nf_res.status_code == 404
        
        # Delete session
        del_res = client.delete(f"/api/capture/sessions/{session_id}")
        assert del_res.status_code == 200
        assert del_res.json().get("ok") is True
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


def test_api_devices_csv_export(client: TestClient):
    """Verify /api/capture/devices/export.csv returns a valid CSV file with headers."""
    res = client.get("/api/capture/devices/export.csv")
    assert res.status_code == 200
    assert "text/csv" in res.headers.get("content-type", "")
    assert "netguard_devices_inventory" in res.headers.get("content-disposition", "")
    
    # Check CSV header row
    lines = res.text.strip().splitlines()
    assert len(lines) >= 1
    header = lines[0]
    for expected_col in ["IP Address", "MAC Address", "Hostname", "Device Type", "Packets"]:
        assert expected_col in header
