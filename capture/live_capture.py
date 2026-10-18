"""
Live passive capture provider.

LIVE MODE uses TShark (`tshark.exe`) exclusively for live capture.
If TShark is unavailable, live mode returns a clear actionable error and marks status as UNAVAILABLE.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional

from capture.tshark_manager import TSHARK_MANAGER, get_tshark_info, list_tshark_interfaces
from visibility.ingest_state import IngestSnapshot

logger = logging.getLogger(__name__)

DEFAULT_BPF = "ip or ip6 or arp"
MAX_CAPTURE_SECONDS = 86400


def capture_provider_status() -> dict[str, Any]:
    """Report whether TShark executable is available for live capture."""
    info = get_tshark_info()
    return {
        "available": info["available"],
        "detail": info["detail"],
        "engine": "TShark",
        "tsharkPath": info["path"],
        "tsharkVersion": info["version"],
    }


def list_capture_interfaces() -> tuple[bool, Optional[str], list[dict[str, Any]]]:
    """Discover local NICs via TShark (-D)."""
    return list_tshark_interfaces()


def resolve_interface_name(requested: str) -> Optional[str]:
    """Resolve an interface index or name."""
    req = (requested or "").strip()
    if not req:
        return None
    ok, _, ifaces = list_tshark_interfaces()
    if not ok:
        return req
    for i in ifaces:
        if i["id"] == req or i["name"] == req or req in i["devicePath"]:
            return i["id"]
    return req


class LiveCaptureManager:
    """Wrapper forwarding live capture actions strictly to TSharkCaptureManager."""

    def __init__(self, on_snapshot: Callable[[IngestSnapshot], None] | None = None) -> None:
        self._on_snapshot = on_snapshot

    @property
    def stats(self) -> dict[str, Any]:
        return TSHARK_MANAGER.get_status()

    def set_on_snapshot(self, cb: Callable[[IngestSnapshot], None] | None) -> None:
        self._on_snapshot = cb

    def start(
        self,
        iface: str,
        snap: IngestSnapshot,
        *,
        seconds: int = 0,
        bpf_filter: Optional[str] = None,
        count: int = 0,
        on_snapshot: Callable[[IngestSnapshot], None] | None = None,
    ) -> tuple[bool, str]:
        _ = (snap, seconds, count, on_snapshot)
        ok, msg = TSHARK_MANAGER.start_capture(iface, bpf_filter=bpf_filter)
        return ok, msg

    def stop(
        self,
        reason: str = "manual",
        expected_session: Optional[int] = None,
    ) -> tuple[bool, str, Optional[IngestSnapshot]]:
        _ = expected_session
        ok, msg = TSHARK_MANAGER.stop_capture(reason=reason)
        return ok, msg, None


# module singleton
MANAGER = LiveCaptureManager()

