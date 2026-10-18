"""Tests for live capture manager, interfaces API, status, and auth."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def capture_mgr():
    from capture.live_capture import LiveCaptureManager
    from visibility.ingest_state import IngestSnapshot

    mgr = LiveCaptureManager()
    yield mgr, IngestSnapshot
    try:
        mgr.stop(reason="manual")
    except Exception:
        pass


def test_list_interfaces_mocked():
    from capture.live_capture import list_capture_interfaces

    ok, err, ifaces = list_capture_interfaces()
    assert isinstance(ok, bool)
    assert isinstance(ifaces, list)
    if ok and ifaces:
        sample = ifaces[0]
        assert "name" in sample
        assert "description" in sample
        assert "isLoopback" in sample


def test_interfaces_endpoint_shape(monkeypatch):
    monkeypatch.delenv("NETGUARD_API_TOKEN", raising=False)

    def fake_list():
        return True, None, [
            {
                "id": "1",
                "name": "1",
                "description": "Mock Ethernet",
                "isLoopback": False,
            }
        ]

    with patch("app.routers.capture_api.list_tshark_interfaces", side_effect=fake_list):
        from app.main import app

        client = TestClient(app)
        r = client.get("/api/capture/interfaces")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["interfaces"][0]["description"] == "Mock Ethernet"


def test_status_fields_default():
    from capture.live_capture import LiveCaptureManager

    mgr = LiveCaptureManager()
    st = mgr.stats
    assert st["running"] is False
    assert st["interface"] is None
    assert "packetsCaptured" in st or "packets" in st
    assert st["error"] is None


def test_capture_status_endpoint(monkeypatch):
    monkeypatch.delenv("NETGUARD_API_TOKEN", raising=False)
    from app.main import app

    client = TestClient(app)
    r = client.get("/api/capture/status")
    assert r.status_code == 200
    body = r.json()
    assert "live" in body
    assert "running" in body
    assert "packets" in body or "packetsCaptured" in body


def test_auth_disabled_allows_api(monkeypatch):
    monkeypatch.delenv("NETGUARD_API_TOKEN", raising=False)
    import app.main as main_mod

    monkeypatch.setattr(main_mod, "API_TOKEN", "")
    client = TestClient(main_mod.app)
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/capture/status").status_code == 200


def test_auth_enabled_requires_bearer(monkeypatch):
    import app.main as main_mod

    monkeypatch.setattr(main_mod, "API_TOKEN", "secret-test-token")
    client = TestClient(main_mod.app)
    assert client.get("/api/health").status_code == 200
    denied = client.get("/api/capture/status")
    assert denied.status_code == 401
    ok = client.get(
        "/api/capture/status",
        headers={"Authorization": "Bearer secret-test-token"},
    )
    assert ok.status_code == 200
    monkeypatch.setattr(main_mod, "API_TOKEN", "")
