"""One-click demo: sample PCAP + ingest + optional detection scan."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database_deps import get_db
from app.demo_assets import sample_pcap_path, write_demo_pcap
from app.routers.detection_api import ScanBody, execute_detection_scan
from capture.pcap_ingest import ingest_pcap_file
from database.models import PcapUpload
from database.persist_visibility import store_snapshot
from database.session import init_db
from visibility.service import get_visibility_service

router = APIRouter(prefix="/demo", tags=["demo"])


@router.get("/status")
def demo_status() -> dict:
    p = sample_pcap_path()
    return {"samplePcapPath": str(p), "sampleExists": p.is_file(), "source": get_visibility_service().source_label}


class DemoLoadBody(BaseModel):
    run_detection_scan: bool = Field(False, description="Chain ML scan after ingest")


@router.post("/load-sample")
def load_sample(body: DemoLoadBody, session: Session = Depends(get_db)) -> dict:
    init_db()
    p = sample_pcap_path()
    if not p.is_file():
        try:
            write_demo_pcap(p)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(500, f"could not write demo pcap: {e}") from e
    try:
        snap = ingest_pcap_file(p)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(422, f"ingest failed: {e}") from e
    pcap = PcapUpload(
        original_name="demo.pcap",
        stored_path=str(p),
        size_bytes=p.stat().st_size,
        packet_count=int(snap.packet_count),
        source="demo",
    )
    session.add(pcap)
    session.flush()
    store_snapshot(session, snap, pcap)
    get_visibility_service().replace_snapshot(snap, "demo-pcap", p)
    out: dict = {"ok": True, "path": str(p), "packets": snap.packet_count, "hosts": len(snap.hosts), "flows": len(snap.flows)}
    if body.run_detection_scan:
        scan_out = execute_detection_scan(session, ScanBody(min_confidence=0.35, clear_existing=False))
        out["detection"] = scan_out
    return out
