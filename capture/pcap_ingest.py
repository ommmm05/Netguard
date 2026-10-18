"""PCAP file ingestion (offline / upload)."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Generator, Optional

from scapy.utils import PcapReader

from capture.decoder import process_packet
from visibility.ingest_state import IngestSnapshot


def iter_packets(path: str | Path) -> Generator[object, None, None]:
    """Yield Scapy packets from a pcap (best-effort format detect)."""
    r = PcapReader(str(path))
    try:
        for pkt in r:
            try:
                if pkt is not None:
                    yield pkt
            except Exception:
                continue
    finally:
        try:
            r.close()
        except Exception:
            pass


def ingest_pcap_file(path: str | Path) -> IngestSnapshot:
    """Build a full visibility snapshot from a capture file (passive)."""
    snap = IngestSnapshot()
    n = 0
    for pkt in iter_packets(path):
        process_packet(pkt, snap)
        n += 1
    if n == 0 and Path(path).exists():
        # empty file still returns empty snapshot
        pass
    snap.run_pattern_hooks()
    return snap


def ingest_packet_iterator(
    path: str | Path, on_progress: Optional[Callable[[int], None]] = None, every: int = 5000
) -> IngestSnapshot:
    """Same as ingest_pcap_file with optional progress callback (packets processed)."""
    snap = IngestSnapshot()
    for i, pkt in enumerate(iter_packets(path), 1):
        process_packet(pkt, snap)
        if on_progress and i % every == 0:
            on_progress(i)
    snap.run_pattern_hooks()
    if on_progress:
        on_progress(snap.packet_count)
    return snap
