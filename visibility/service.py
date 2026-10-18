"""
Global in-memory visibility snapshot, optionally hydrated from the latest PCAP in DB.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from database.models import PcapUpload
from database.session import SessionLocal, init_db
from visibility.ingest_state import IngestSnapshot


class VisibilityService:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._snap: IngestSnapshot = IngestSnapshot()
        self._source: str = "empty"
        self._last_pcap: Optional[Path] = None

    def get_snapshot(self) -> IngestSnapshot:
        with self._lock:
            return self._snap

    def replace_snapshot(self, snap: IngestSnapshot, source: str, pcap_path: Path | None = None) -> None:
        with self._lock:
            self._snap = snap
            self._source = source
            self._last_pcap = pcap_path

    @property
    def source_label(self) -> str:
        return self._source

    @property
    def last_pcap(self) -> Optional[Path]:
        return self._last_pcap

    def try_reload_from_db(self) -> None:
        """Re-ingest the latest PCAP on disk (after API restart)."""
        init_db()
        session: Session = SessionLocal()
        try:
            last = session.execute(
                select(PcapUpload).order_by(PcapUpload.id.desc())
            ).scalars().first()
            if last and Path(last.stored_path).is_file():
                from capture.pcap_ingest import ingest_pcap_file

                self.replace_snapshot(ingest_pcap_file(last.stored_path), "db-restore", Path(last.stored_path))
        except Exception:
            pass
        finally:
            session.close()


_SVC: Optional[VisibilityService] = None
_SVC_LOCK = threading.Lock()


def get_visibility_service() -> VisibilityService:
    global _SVC
    with _SVC_LOCK:
        if _SVC is None:
            _SVC = VisibilityService()
        return _SVC
