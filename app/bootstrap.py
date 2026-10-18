"""Optional first-run demo: NETGUARD_AUTO_DEMO=1 loads synthetic PCAP + scan."""

from __future__ import annotations

import logging
import os

log = logging.getLogger("netguard.bootstrap")


def try_auto_demo() -> None:
    if os.environ.get("NETGUARD_AUTO_DEMO", "").lower() not in ("1", "true", "yes"):
        return
    try:
        from database.session import SessionLocal
        from app.demo_assets import sample_pcap_path, write_demo_pcap
        from capture.pcap_ingest import ingest_pcap_file
        from database.models import PcapUpload
        from database.persist_visibility import store_snapshot
        from app.routers.detection_api import ScanBody, execute_detection_scan
        from visibility.service import get_visibility_service

        p = sample_pcap_path()
        if not p.is_file():
            write_demo_pcap(p)
        snap = ingest_pcap_file(p)
        with SessionLocal() as session:
            try:
                pcap = PcapUpload(
                    original_name="auto-demo.pcap",
                    stored_path=str(p),
                    size_bytes=p.stat().st_size,
                    packet_count=int(snap.packet_count),
                    source="demo",
                )
                session.add(pcap)
                session.flush()
                store_snapshot(session, snap, pcap)
                execute_detection_scan(session, ScanBody(min_confidence=0.35, clear_existing=False))
                session.commit()
            except Exception:
                session.rollback()
                raise
        get_visibility_service().replace_snapshot(snap, "auto-demo", p)
        log.info("NETGUARD_AUTO_DEMO: loaded %s (%s pkts)", p, snap.packet_count)
    except Exception as e:  # noqa: BLE001
        log.warning("NETGUARD_AUTO_DEMO skipped: %s", e)
