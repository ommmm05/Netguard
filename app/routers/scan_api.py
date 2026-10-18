"""Active LAN scan API — ARP + nmap (background thread)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from visibility.network_scanner import (
    build_cytoscape_elements,
    get_local_subnet,
    get_scan_state,
    start_network_scan,
)

router = APIRouter(prefix="/scan", tags=["scan"])


@router.get("/subnet")
def subnet_info() -> dict:
    """Detect local subnet / gateway without starting a scan."""
    try:
        subnet, local_ip, gateway_ip = get_local_subnet()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"subnet detection failed: {e}") from e
    return {
        "subnet": subnet,
        "localIp": local_ip,
        "gatewayIp": gateway_ip,
    }


@router.post("/start")
def scan_start() -> dict:
    """
    Start a background ARP + nmap LAN scan.
    Poll GET /api/scan/status for progress; hosts stream into /api/visibility/* as discovered.
    """
    state = start_network_scan()
    if state.get("status") == "error" and not state.get("hosts"):
        # Soft-fail: still return state so UI can show the message
        return {"ok": False, **_public_state(state)}
    return {"ok": True, **_public_state(state)}


@router.get("/status")
def scan_status() -> dict:
    state = get_scan_state()
    elements = build_cytoscape_elements(
        state.get("hosts") or [],
        gateway_ip=state.get("gateway_ip"),
        local_ip=state.get("local_ip"),
    )
    return {**_public_state(state), "elements": elements}


@router.get("/hosts")
def scan_hosts() -> dict:
    state = get_scan_state()
    return {
        "status": state.get("status"),
        "hosts": state.get("hosts") or [],
        "progress": state.get("progress", 0),
    }


def _public_state(state: dict) -> dict:
    return {
        "status": state.get("status", "idle"),
        "progress": int(state.get("progress") or 0),
        "hosts": state.get("hosts") or [],
        "subnet": state.get("subnet"),
        "localIp": state.get("local_ip"),
        "gatewayIp": state.get("gateway_ip"),
        "error": state.get("error"),
        "message": state.get("message"),
        "startedAt": state.get("started_at"),
        "finishedAt": state.get("finished_at"),
        "scanning": state.get("status") == "scanning",
    }
