from __future__ import annotations

import csv
import io
import logging
import os
import re
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.database_deps import get_db
from config import find_tshark_executable
from capture.tshark_manager import (
    CAPTURES_DIR,
    TSHARK_MANAGER,
    get_tshark_info,
    list_tshark_interfaces,
)
from capture.pcap_ingest import ingest_pcap_file
from database.models import PcapUpload
from database.persist_visibility import store_snapshot
from database.session import SessionLocal, init_db
from realtime.event_broadcaster import BROADCASTER
from visibility.ingest_state import IngestSnapshot
from visibility.service import get_visibility_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/capture", tags=["capture"])

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

LIVE_UNSAVED_PATH = "live://unsaved"


@router.get(
    "/interfaces",
    summary="List TShark capture interfaces",
    description="Discover network interfaces via TShark (-D). Reports executable location and version details.",
)
def list_interfaces() -> dict:
    ok, err, interfaces = list_tshark_interfaces()
    info = get_tshark_info()
    return {
        "ok": ok,
        "interfaces": interfaces,
        "error": err if not ok else None,
        "captureEngine": "TShark",
        "captureAvailable": info["available"],
        "tsharkPath": info["path"],
        "tsharkVersion": info["version"],
        "tsharkDetail": info["detail"],
        "defaultBpf": "",
    }


class LiveStart(BaseModel):
    interface: str = Field(
        ...,
        min_length=1,
        description="Interface index or device path from GET /api/capture/interfaces",
    )
    seconds: int = Field(
        0,
        description="0 = run until Stop; otherwise auto-stop after N seconds (max 86400)",
    )
    bpfFilter: Optional[str] = Field(
        None,
        description="Optional BPF capture filter syntax (e.g. 'tcp or udp', 'port 80')",
    )

    @field_validator("interface")
    @classmethod
    def _validate_iface(cls, v: str) -> str:
        s = (v or "").strip()
        if not s:
            raise ValueError("interface is required")
        return s


@router.post(
    "/pcap",
    summary="Upload PCAP",
    description="Upload a PCAP/PCAPNG file for offline passive analysis and replace the visibility snapshot.",
)
async def upload_pcap(
    file: UploadFile = File(...),
    session: Session = Depends(get_db),
) -> dict:
    init_db()
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "empty file")
    max_bytes = 100 * 1024 * 1024  # 100 MB
    if len(raw) > max_bytes:
        raise HTTPException(413, "PCAP too large (max 100 MB)")
    name = (file.filename or "capture.pcap").replace("\\", "_").replace("/", "_")
    lower = name.lower()
    if not lower.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(400, "expected .pcap / .pcapng / .cap file")
    u = f"{uuid.uuid4().hex}_{name}"
    path = UPLOAD_DIR / u
    path.write_bytes(raw)
    try:
        snap = ingest_pcap_file(path)
    except Exception as e:  # noqa: BLE001
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise HTTPException(422, f"pcap parse failed: {e}") from e
    pcap = PcapUpload(
        original_name=name,
        stored_path=str(path),
        size_bytes=len(raw),
        packet_count=int(snap.packet_count),
        source="upload",
    )
    session.add(pcap)
    session.flush()
    store_snapshot(session, snap, pcap)
    get_visibility_service().replace_snapshot(snap, "pcap", path)
    talkers = snap.top_talkers()
    top = talkers[0]["ip"] if talkers else None
    protocols = sorted({r.get("protocol") for r in (f.to_row() for f in snap.flows.values()) if r.get("protocol")})
    return {
        "ok": True,
        "pcapId": pcap.id,
        "packets": snap.packet_count,
        "hosts": len(snap.hosts),
        "flows": len(snap.flows),
        "uniqueIps": len(snap.hosts),
        "protocols": protocols,
        "topTalker": top,
    }


@router.post(
    "/live/start",
    summary="Start live TShark capture",
    description="Start real TShark live packet capture on the selected interface.",
)
def live_start(body: LiveStart) -> dict:
    init_db()
    info = get_tshark_info()
    if not info["available"]:
        raise HTTPException(status_code=503, detail=info["detail"])

    if TSHARK_MANAGER.is_running:
        raise HTTPException(status_code=409, detail="Live TShark capture is already running")

    ok, msg = TSHARK_MANAGER.start_capture(body.interface, bpf_filter=body.bpfFilter)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    return {"ok": True, "message": msg, "stats": TSHARK_MANAGER.get_status()}


@router.post(
    "/live/stop",
    summary="Stop live TShark capture",
    description="Stop the active TShark live capture subprocess.",
)
def live_stop() -> dict:
    ok, msg = TSHARK_MANAGER.stop_capture(reason="manual")
    if not ok:
        raise HTTPException(400, msg)
    return {
        "ok": True,
        "message": msg,
        "stats": TSHARK_MANAGER.get_status(),
    }


@router.get(
    "/status",
    summary="Capture status",
    description="Full status of TShark capture engine, metrics, and diagnostic command info.",
)
def capture_status() -> dict:
    st = TSHARK_MANAGER.get_status()
    return {
        "live": st,
        "source": get_visibility_service().source_label,
        "running": bool(st.get("running")),
        "interface": st.get("interface"),
        "started_at": st.get("startedAt"),
        "elapsed_seconds": st.get("elapsedSeconds"),
        "packets": st.get("packetsCaptured"),
        "packetsProcessed": st.get("packetsProcessed"),
        "threatsDetected": st.get("threatsDetected"),
        "error": st.get("error"),
        "stop_reason": st.get("stopReason"),
        "diagnosticInfo": st.get("diagnosticInfo"),
    }


@router.get(
    "/live/stream",
    summary="SSE Live Event Stream",
    description="Server-Sent Events (SSE) stream pushing real-time packet telemetry and threat alerts.",
)
async def live_stream():
    q = BROADCASTER.subscribe()
    return StreamingResponse(
        BROADCASTER.stream_events(q),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/live/packets",
    summary="Recent Live Packets",
    description="Return recent live parsed packet telemetry (REST fallback).",
)
def live_packets(limit: int = 50) -> dict:
    return {"packets": TSHARK_MANAGER.get_recent_packets(limit=limit)}


@router.get(
    "/live/alerts",
    summary="Recent Live Threat Alerts",
    description="Return recent live threat/flow alerts (REST fallback).",
)
def live_alerts(limit: int = 50) -> dict:
    return {"alerts": TSHARK_MANAGER.get_recent_alerts(limit=limit)}


# =========================================================================
# CAPTURE SESSIONS & WIRESHARK PCAPNG EXPORT ENDPOINTS
# =========================================================================

@router.get(
    "/sessions",
    summary="List capture sessions",
    description="Retrieve list of all saved and active TShark live capture sessions with metadata.",
)
def list_capture_sessions() -> dict:
    sessions = TSHARK_MANAGER.get_capture_sessions()
    return {"ok": True, "sessions": sessions, "total": len(sessions)}


@router.get(
    "/sessions/{capture_id}",
    summary="Get capture session metadata",
    description="Retrieve metadata for a specific capture session.",
)
def get_capture_session_metadata(capture_id: str) -> dict:
    if not re.match(r"^[a-zA-Z0-9_\-]+$", capture_id):
        raise HTTPException(status_code=400, detail="Invalid capture session ID format")
    sess = TSHARK_MANAGER.get_capture_session(capture_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Capture session not found")
    return {"ok": True, "session": sess}


@router.get(
    "/sessions/{capture_id}/download",
    summary="Download real PCAPNG capture file",
    description="Download genuine Wireshark-compatible PCAPNG packet capture file written by TShark.",
)
def download_capture_file(capture_id: str):
    if not re.match(r"^[a-zA-Z0-9_\-]+$", capture_id):
        raise HTTPException(status_code=400, detail="Invalid capture session ID format")
    sess = TSHARK_MANAGER.get_capture_session(capture_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Capture session not found")

    # If capture is still actively running, require stopping first
    st = TSHARK_MANAGER.get_status()
    if st.get("running") and st.get("activeSessionId") == capture_id:
        raise HTTPException(
            status_code=409,
            detail="Capture is still running. Stop capture to download the complete PCAPNG.",
        )

    filepath = Path(sess["filepath"]).resolve()
    # Security: Verify path is strictly within managed CAPTURES_DIR
    try:
        resolved_captures = CAPTURES_DIR.resolve()
        if not str(filepath).startswith(str(resolved_captures)):
            raise HTTPException(status_code=403, detail="Access denied: path traversal attempt")
    except Exception as e:
        raise HTTPException(status_code=403, detail="Path validation error") from e

    if not filepath.is_file():
        raise HTTPException(status_code=404, detail="Capture file does not exist on disk")

    filename = sess.get("filename") or f"{capture_id}.pcapng"
    return FileResponse(
        path=str(filepath),
        filename=filename,
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache",
        },
    )


@router.delete(
    "/sessions/{capture_id}",
    summary="Delete capture session",
    description="Delete capture session metadata and file.",
)
def delete_capture_session(capture_id: str) -> dict:
    if not re.match(r"^[a-zA-Z0-9_\-]+$", capture_id):
        raise HTTPException(status_code=400, detail="Invalid capture session ID format")
    ok = TSHARK_MANAGER.delete_capture_session(capture_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Could not delete capture session (may be active or not found)")
    return {"ok": True, "message": f"Session {capture_id} deleted"}


@router.get(
    "/sessions/{capture_id}/packets.csv",
    summary="Export capture packets as CSV",
    description="Export packet metadata for capture session in CSV format using TShark or recent memory.",
)
def export_session_packets_csv(capture_id: str):
    if not re.match(r"^[a-zA-Z0-9_\-]+$", capture_id):
        raise HTTPException(status_code=400, detail="Invalid capture session ID format")
    sess = TSHARK_MANAGER.get_capture_session(capture_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Capture session not found")

    filepath = Path(sess["filepath"]).resolve()
    resolved_captures = CAPTURES_DIR.resolve()
    if not str(filepath).startswith(str(resolved_captures)):
        raise HTTPException(status_code=403, detail="Access denied")

    t_path, _ = find_tshark_executable()
    if filepath.is_file() and t_path and os.path.isfile(t_path):
        cmd = [
            t_path,
            "-r",
            str(filepath),
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
            "-e",
            "frame.number",
            "-e",
            "frame.time_relative",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "frame.len",
            "-e",
            "_ws.col.Info",
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0 and res.stdout:
                return Response(
                    content=res.stdout,
                    media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{capture_id}_packets.csv"'},
                )
        except Exception as e:
            logger.warning("Failed TShark CSV extraction, falling back: %s", e)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Frame", "Timestamp", "Src IP", "Dst IP", "Protocol", "Length", "Info"])
    for pkt in TSHARK_MANAGER.get_recent_packets(limit=500):
        writer.writerow([
            pkt.get("frameNumber", ""),
            pkt.get("timestamp", ""),
            pkt.get("srcIp", ""),
            pkt.get("dstIp", ""),
            pkt.get("transportProtocol", "") or pkt.get("networkProtocol", ""),
            pkt.get("length", ""),
            pkt.get("protocolInfo", ""),
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{capture_id}_packets.csv"'},
    )


@router.get(
    "/sessions/{capture_id}/packets.json",
    summary="Export capture packets as JSON",
    description="Export packet metadata for capture session as JSON array.",
)
def export_session_packets_json(capture_id: str):
    if not re.match(r"^[a-zA-Z0-9_\-]+$", capture_id):
        raise HTTPException(status_code=400, detail="Invalid capture session ID format")
    sess = TSHARK_MANAGER.get_capture_session(capture_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Capture session not found")

    packets = TSHARK_MANAGER.get_recent_packets(limit=500)
    return {
        "ok": True,
        "sessionId": capture_id,
        "session": sess,
        "packetCount": len(packets),
        "packets": packets,
    }


@router.get(
    "/devices/export.csv",
    summary="Export discovered devices as CSV",
    description="Export real discovered network devices/assets inventory from visibility service as CSV.",
)
def export_devices_csv():
    snap = get_visibility_service().get_snapshot()
    hosts = snap.hosts if snap else {}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IP Address",
        "MAC Address",
        "Hostname",
        "Device Type",
        "Open Ports",
        "Risk Score",
        "Status",
        "Packets",
        "Bytes",
        "First Seen",
        "Last Seen",
    ])

    for ip, h in sorted(hosts.items(), key=lambda item: item[0]):
        if isinstance(h, dict):
            open_ports = sorted(h.get("ports") or [])
            open_ports_str = ";".join(str(p) for p in open_ports)
            first_ts = h.get("first_ts")
            last_ts = h.get("last_ts")
            first_seen_str = datetime.fromtimestamp(first_ts).isoformat() if first_ts else ""
            last_seen_str = datetime.fromtimestamp(last_ts).isoformat() if last_ts else ""
            mac = h.get("mac") or ""
            hostname = h.get("hostname") or ""
            role = h.get("device_type") or h.get("role") or "Host"
            risk_score = h.get("risk_score") or (snap._risk_score(ip) if hasattr(snap, "_risk_score") else 10)
            status = h.get("status") or "active"
            pkt_count = h.get("packet_count") or h.get("packets") or 0
            byte_count = h.get("byte_count") or h.get("bytes") or 0
        else:
            open_ports_str = ";".join(str(p) for p in (getattr(h, "open_ports", None) or []))
            first_seen = getattr(h, "first_seen", None)
            last_seen = getattr(h, "last_seen", None)
            first_seen_str = datetime.fromtimestamp(first_seen).isoformat() if first_seen else ""
            last_seen_str = datetime.fromtimestamp(last_seen).isoformat() if last_seen else ""
            mac = getattr(h, "mac", "") or ""
            hostname = getattr(h, "hostname", "") or ""
            role = getattr(h, "device_type", None) or getattr(h, "role", None) or "Host"
            risk_score = getattr(h, "risk_score", 10)
            status = getattr(h, "status", "active")
            pkt_count = getattr(h, "packet_count", None) or getattr(h, "packets", 0) or 0
            byte_count = getattr(h, "byte_count", None) or getattr(h, "bytes", 0) or 0

        writer.writerow([
            ip,
            mac,
            hostname,
            role,
            open_ports_str,
            risk_score,
            status,
            pkt_count,
            byte_count,
            first_seen_str,
            last_seen_str,
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="netguard_devices_inventory.csv"'},
    )

