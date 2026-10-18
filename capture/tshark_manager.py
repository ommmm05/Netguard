"""
capture/tshark_manager.py — TShark Live Capture Engine & Pipeline Manager.

Manages the real TShark live packet capture subprocess, streams stdout line-by-line,
parses packets, aggregates bidirectional flows, runs ML threat detection, persists alerts,
and streams real-time telemetry to the SOC dashboard.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from config import TSHARK_PATH, TSHARK_STATUS_DETAIL, find_tshark_executable
from capture.flow_tracker import FlowTracker, FlowState
from capture.packet_parser import ParsedPacket, parse_tshark_frame
from database.models import MLAlert
from database.session import SessionLocal, init_db
from detection.adapter import evaluate_flow_state, format_transparent_ensemble_details
from detection.inference import make_alert_id
from realtime.event_broadcaster import BROADCASTER

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
CAPTURES_DIR = BASE_DIR / "data" / "captures"
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
SESSIONS_INDEX_FILE = CAPTURES_DIR / "sessions_index.json"
MAX_SESSIONS_RETENTION = 20


def format_size(size_bytes: int) -> str:
    """Format byte size into human readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def get_tshark_info() -> dict[str, Any]:
    """Inspect TShark executable availability and version details."""
    path, detail = find_tshark_executable()
    available = path is not None and os.path.isfile(path)
    version_str = "Unavailable"
    if available:
        try:
            res = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0 and res.stdout:
                version_str = res.stdout.splitlines()[0]
        except Exception as e:
            version_str = f"Error querying version: {e}"

    return {
        "available": available,
        "path": path,
        "detail": detail,
        "version": version_str,
    }


def list_tshark_interfaces() -> tuple[bool, Optional[str], list[dict[str, Any]]]:
    """
    Discover network interfaces available to TShark via `tshark -D`.
    Returns (ok, error_message, list_of_interfaces).
    """
    path, detail = find_tshark_executable()
    if not path or not os.path.isfile(path):
        return False, detail, []

    try:
        res = subprocess.run(
            [path, "-D"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode != 0:
            err_msg = res.stderr.strip() or f"tshark -D returned code {res.returncode}"
            return False, err_msg, []

        interfaces: list[dict[str, Any]] = []
        for line in res.stdout.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            # Output format: "1. \Device\NPF_{...} (Wi-Fi)" or "1. eth0"
            parts = line_str.split(" ", 1)
            if len(parts) == 2 and parts[0].rstrip(".").isdigit():
                index_str = parts[0].rstrip(".")
                raw_desc = parts[1]
                name = index_str  # Use index or device string
                friendly_desc = raw_desc
                if "(" in raw_desc and raw_desc.endswith(")"):
                    # Extract friendly name in parentheses
                    dev_part, desc_part = raw_desc.rsplit("(", 1)
                    name = index_str
                    friendly_desc = f"{desc_part.rstrip(')')} ({dev_part.strip()})"

                is_loopback = "loopback" in raw_desc.lower() or "npf_loopback" in raw_desc.lower()
                interfaces.append({
                    "id": index_str,
                    "name": name,
                    "devicePath": raw_desc.split(" ")[0],
                    "description": friendly_desc,
                    "isLoopback": is_loopback,
                })

        return True, None, interfaces
    except Exception as e:
        logger.error("Failed to discover TShark interfaces: %s", e)
        return False, f"TShark interface discovery failed: {e}", []


class TSharkCaptureManager:
    """Thread-safe manager for live TShark capture and real-time threat detection."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._proc: Optional[subprocess.Popen] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._flusher_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._recent_packets: deque[dict[str, Any]] = deque(maxlen=100)
        self._recent_alerts: deque[dict[str, Any]] = deque(maxlen=100)

        # Telemetry & Statistics
        self._running = False
        self._interface: Optional[str] = None
        self._bpf_filter: Optional[str] = None
        self._started_at: Optional[float] = None
        self._elapsed_seconds = 0.0
        self._packets_captured = 0
        self._packets_parsed = 0
        self._packets_processed = 0
        self._threats_detected = 0
        self._benign_count = 0
        self._anomaly_count = 0
        self._capture_errors: Optional[str] = None
        self._stop_reason: Optional[str] = None

        # Capture file & session tracking
        self._active_session: Optional[dict[str, Any]] = None

        # Flow tracker
        self._flow_tracker = FlowTracker(on_flow_complete=self._on_flow_completed)

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def _load_sessions_index(self) -> list[dict[str, Any]]:
        """Load list of recorded sessions from SESSIONS_INDEX_FILE."""
        if not SESSIONS_INDEX_FILE.exists():
            return []
        try:
            with open(SESSIONS_INDEX_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except Exception as e:
            logger.warning("Failed to read sessions index: %s", e)
        return []

    def _save_sessions_index(self, sessions: list[dict[str, Any]]) -> None:
        """Save list of sessions to SESSIONS_INDEX_FILE."""
        try:
            temp_file = CAPTURES_DIR / "sessions_index.json.tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(sessions, f, indent=2)
            temp_file.replace(SESSIONS_INDEX_FILE)
        except Exception as e:
            logger.error("Failed to save sessions index: %s", e)

    def _prune_old_sessions(self) -> None:
        """Prune sessions older than MAX_SESSIONS_RETENTION to manage disk space."""
        sessions = self._load_sessions_index()
        if len(sessions) <= MAX_SESSIONS_RETENTION:
            return
        to_keep = sessions[:MAX_SESSIONS_RETENTION]
        to_remove = sessions[MAX_SESSIONS_RETENTION:]
        for s in to_remove:
            fpath = s.get("filepath")
            if fpath and os.path.isfile(fpath):
                try:
                    os.remove(fpath)
                    logger.info("Pruned old capture file: %s", fpath)
                except OSError as e:
                    logger.warning("Could not delete old capture file %s: %s", fpath, e)
        self._save_sessions_index(to_keep)

    def _record_session(self, session_data: dict[str, Any]) -> None:
        """Insert or update session in the index and prune old ones."""
        sessions = self._load_sessions_index()
        existing_idx = next((i for i, s in enumerate(sessions) if s["id"] == session_data["id"]), None)
        if existing_idx is not None:
            sessions[existing_idx] = session_data
        else:
            sessions.insert(0, session_data)
        self._save_sessions_index(sessions)
        self._prune_old_sessions()

    def get_capture_sessions(self) -> list[dict[str, Any]]:
        """Return all available capture sessions, including currently active session if running."""
        with self._lock:
            saved = self._load_sessions_index()
            # Update file size and stats for saved sessions if file on disk
            for s in saved:
                fpath = s.get("filepath")
                if fpath and os.path.isfile(fpath):
                    sz = os.path.getsize(fpath)
                    s["fileSizeBytes"] = sz
                    s["fileSize"] = format_size(sz)
                elif fpath and not os.path.isfile(fpath):
                    s["status"] = "missing_file"

            if self._running and self._active_session:
                act = dict(self._active_session)
                act["packetCount"] = self._packets_captured
                if self._started_at:
                    act["durationSeconds"] = round(time.time() - self._started_at, 1)
                fpath = act.get("filepath")
                if fpath and os.path.isfile(fpath):
                    sz = os.path.getsize(fpath)
                    act["fileSizeBytes"] = sz
                    act["fileSize"] = format_size(sz)
                return [act] + [s for s in saved if s["id"] != act["id"]]
            return saved

    def get_capture_session(self, capture_id: str) -> Optional[dict[str, Any]]:
        """Find session metadata by capture_id."""
        with self._lock:
            if self._active_session and self._active_session["id"] == capture_id:
                act = dict(self._active_session)
                act["packetCount"] = self._packets_captured
                if self._started_at:
                    act["durationSeconds"] = round(time.time() - self._started_at, 1)
                fpath = act.get("filepath")
                if fpath and os.path.isfile(fpath):
                    sz = os.path.getsize(fpath)
                    act["fileSizeBytes"] = sz
                    act["fileSize"] = format_size(sz)
                return act

            sessions = self._load_sessions_index()
            for s in sessions:
                if s["id"] == capture_id:
                    fpath = s.get("filepath")
                    if fpath and os.path.isfile(fpath):
                        sz = os.path.getsize(fpath)
                        s["fileSizeBytes"] = sz
                        s["fileSize"] = format_size(sz)
                    return s
            return None

    def delete_capture_session(self, capture_id: str) -> bool:
        """Delete capture session metadata and .pcapng file."""
        with self._lock:
            if self._active_session and self._active_session["id"] == capture_id and self._running:
                return False
            sessions = self._load_sessions_index()
            target = next((s for s in sessions if s["id"] == capture_id), None)
            if not target:
                return False
            fpath = target.get("filepath")
            if fpath and os.path.isfile(fpath):
                try:
                    os.remove(fpath)
                except OSError:
                    pass
            updated = [s for s in sessions if s["id"] != capture_id]
            self._save_sessions_index(updated)
            return True

    def get_status(self) -> dict[str, Any]:
        """Return full capture status metrics."""
        with self._lock:
            t_path, t_detail = find_tshark_executable()
            elapsed = 0.0
            if self._running and self._started_at:
                elapsed = round(time.time() - self._started_at, 2)
            elif not self._running and self._elapsed_seconds:
                elapsed = self._elapsed_seconds

            cmd_info = {
                "executable": t_path or "Not Found",
                "interface": self._interface or "None",
                "bpfFilter": self._bpf_filter or "None",
                "outputMode": "-w <capture.pcapng> -P -l -T ek (PCAPNG + NDJSON stdout)",
            }

            active_id = self._active_session["id"] if self._active_session else None
            active_file = self._active_session["filename"] if self._active_session else None

            return {
                "engine": "TShark",
                "tsharkPath": t_path,
                "tsharkAvailable": t_path is not None and os.path.isfile(t_path),
                "tsharkDetail": t_detail,
                "running": self._running,
                "interface": self._interface,
                "bpfFilter": self._bpf_filter,
                "startedAt": self._started_at,
                "elapsedSeconds": elapsed,
                "packetsCaptured": self._packets_captured,
                "packetsParsed": self._packets_parsed,
                "packetsProcessed": self._packets_processed,
                "activeFlows": self._flow_tracker.active_flows_count,
                "completedFlows": self._flow_tracker.completed_flows_count,
                "threatsDetected": self._threats_detected,
                "benignCount": self._benign_count,
                "anomalyCount": self._anomaly_count,
                "error": self._capture_errors,
                "stopReason": self._stop_reason,
                "activeSessionId": active_id,
                "activeCaptureFile": active_file,
                "diagnosticInfo": cmd_info,
            }

    def start_capture(self, interface: str, bpf_filter: Optional[str] = None) -> tuple[bool, str]:
        """
        Start live TShark capture on specified interface with simultaneous PCAPNG file persistence.
        Returns (success, message).
        """
        t_path, detail = find_tshark_executable()
        if not t_path or not os.path.isfile(t_path):
            return False, f"TShark unavailable: {detail}"

        with self._lock:
            if self._running:
                return False, "Live TShark capture is already running."

            self._stop_event.clear()
            self._proc = None
            self._interface = interface
            self._bpf_filter = (bpf_filter or "").strip() or None
            self._started_at = time.time()
            self._elapsed_seconds = 0.0
            self._packets_captured = 0
            self._packets_parsed = 0
            self._packets_processed = 0
            self._threats_detected = 0
            self._benign_count = 0
            self._anomaly_count = 0
            self._capture_errors = None
            self._stop_reason = None
            self._flow_tracker.clear()
            self._recent_packets.clear()
            self._recent_alerts.clear()

            # Initialize unique capture session & output PCAPNG file
            now_dt = datetime.now()
            session_id = f"netguard_capture_{now_dt.strftime('%Y-%m-%d_%H-%M-%S')}"
            filename = f"{session_id}.pcapng"
            filepath = CAPTURES_DIR / filename

            self._active_session = {
                "id": session_id,
                "filename": filename,
                "filepath": str(filepath),
                "interface": str(interface),
                "bpfFilter": self._bpf_filter,
                "startTime": now_dt.isoformat(),
                "endTime": None,
                "durationSeconds": 0.0,
                "packetCount": 0,
                "fileSizeBytes": 0,
                "fileSize": "0 B",
                "status": "running",
            }

            # Build safe command argument list with dual output (-w for PCAPNG + -P -l -T ek for live stream)
            cmd = [t_path, "-i", str(interface), "-w", str(filepath), "-P", "-l", "-T", "ek"]
            if self._bpf_filter:
                cmd.extend(["-f", self._bpf_filter])

            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
            except (OSError, PermissionError, Exception) as e:
                self._running = False
                self._capture_errors = str(e)
                logger.error("Failed to start TShark subprocess: %s", e)
                return False, f"Failed to start TShark subprocess: {e}"

            self._running = True

            # Start background reader thread
            self._reader_thread = threading.Thread(
                target=self._stdout_reader_loop,
                daemon=True,
                name="tshark-stdout-reader",
            )
            self._reader_thread.start()

            # Start background flow flusher thread (flushes expired flows every 2s)
            self._flusher_thread = threading.Thread(
                target=self._flow_flusher_loop,
                daemon=True,
                name="tshark-flow-flusher",
            )
            self._flusher_thread.start()

            logger.info("TShark live capture started on interface %s (BPF: %s)", interface, self._bpf_filter)
            return True, f"TShark capture started on interface {interface}"

    def stop_capture(self, reason: str = "manual") -> tuple[bool, str]:
        """Stop live TShark capture and clean up subprocess and background threads."""
        proc = None
        with self._lock:
            if not self._running:
                return True, "Capture already stopped"

            self._running = False
            self._stop_reason = reason
            proc = self._proc
            self._proc = None
            if self._started_at:
                self._elapsed_seconds = round(time.time() - self._started_at, 2)

        self._stop_event.set()

        # Terminate TShark process cleanly
        if proc is not None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1.0)
            except Exception as e:
                logger.warning("Error terminating TShark process: %s", e)

        # Flush remaining active flows into ML pipeline
        try:
            self._flow_tracker.flush_all_flows()
        except Exception:
            pass

        # Finalize and record capture session
        with self._lock:
            if self._active_session:
                end_dt = datetime.now()
                self._active_session["endTime"] = end_dt.isoformat()
                self._active_session["durationSeconds"] = self._elapsed_seconds
                self._active_session["packetCount"] = self._packets_captured
                self._active_session["status"] = "completed" if reason != "error" else "error"
                try:
                    fpath = self._active_session.get("filepath")
                    if fpath and os.path.isfile(fpath):
                        sz = os.path.getsize(fpath)
                        self._active_session["fileSizeBytes"] = sz
                        self._active_session["fileSize"] = format_size(sz)
                except Exception:
                    pass
                self._record_session(self._active_session)
                self._active_session = None

        logger.info("TShark live capture stopped (reason: %s)", reason)
        return True, "Capture stopped"

    def _stdout_reader_loop(self) -> None:
        """Background thread loop reading TShark stdout line-by-line non-blockingly."""
        proc = self._proc
        if proc is None or proc.stdout is None:
            return

        frame_counter = 0

        try:
            for raw_line in proc.stdout:
                if self._stop_event.is_set() or not self._running:
                    break

                line = raw_line.strip()
                if not line:
                    continue

                with self._lock:
                    self._packets_captured += 1
                    if self._active_session:
                        self._active_session["packetCount"] = self._packets_captured

                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                frame_counter += 1
                pkt = parse_tshark_frame(obj, frame_counter=frame_counter)
                if pkt is None:
                    continue

                with self._lock:
                    self._packets_parsed += 1

                # 1. Real-time Packet Telemetry Broadcast to SSE / UI
                pkt_dict = pkt.to_dict()
                self._recent_packets.append(pkt_dict)
                BROADCASTER.publish_event("packet", pkt_dict)

                # 2. Feed Packet into Flow Tracker
                try:
                    self._flow_tracker.process_packet(pkt)
                    with self._lock:
                        self._packets_processed += 1
                except Exception as e:
                    logger.debug("Flow tracker error processing packet: %s", e)

        except Exception as e:
            logger.error("Error in TShark stdout reader: %s", e)
            with self._lock:
                self._capture_errors = str(e)
        finally:
            with self._lock:
                self._running = False
                if self._active_session:
                    end_dt = datetime.now()
                    self._active_session["endTime"] = end_dt.isoformat()
                    self._active_session["durationSeconds"] = self._elapsed_seconds
                    self._active_session["packetCount"] = self._packets_captured
                    self._active_session["status"] = "completed" if not self._capture_errors else "error"
                    try:
                        fpath = self._active_session.get("filepath")
                        if fpath and os.path.isfile(fpath):
                            sz = os.path.getsize(fpath)
                            self._active_session["fileSizeBytes"] = sz
                            self._active_session["fileSize"] = format_size(sz)
                    except Exception:
                        pass
                    self._record_session(self._active_session)
                    self._active_session = None

    def _flow_flusher_loop(self) -> None:
        """Background thread loop periodically purging expired flows."""
        while not self._stop_event.is_set() and self._running:
            time.sleep(2.0)
            try:
                self._flow_tracker.purge_expired_flows()
            except Exception as e:
                logger.debug("Error purging expired flows: %s", e)

    def _on_flow_completed(self, flow: FlowState) -> None:
        """
        Callback triggered when a 5-tuple flow completes or expires.
        Runs ML detection on the flow's 20-dim feature vector, stores alerts in DB, and streams to UI.
        """
        try:
            flow_dict, result = evaluate_flow_state(flow)

            with self._lock:
                if result.attack_type == "Benign":
                    self._benign_count += 1
                elif result.attack_type == "Anomaly":
                    self._anomaly_count += 1
                else:
                    self._threats_detected += 1

            if not result.alert:
                return

            aid = make_alert_id()
            diag = format_transparent_ensemble_details(result)

            alert_data = {
                "id": aid,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "severity": result.severity,
                "title": result.title,
                "description": f"Live flow {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port} ({flow.protocol})",
                "srcIp": flow.src_ip,
                "dstIp": flow.dst_ip,
                "srcPort": flow.src_port,
                "dstPort": flow.dst_port,
                "protocol": flow.protocol,
                "attackType": result.attack_type,
                "confidence": result.confidence,
                "model": result.model,
                "status": "open",
                "features": {
                    "dst_port": flow.dst_port,
                    "flow_duration": flow.duration,
                    "byte_count": flow.total_bytes,
                    "packet_count": flow.total_packets,
                    **diag,
                },
            }

            # 1. Save alert to SQLite Database
            init_db()
            session = SessionLocal()
            try:
                alert_obj = MLAlert(
                    id=aid,
                    created_at=datetime.utcnow(),
                    severity=result.severity,
                    title=result.title,
                    description=alert_data["description"],
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    protocol=flow.protocol,
                    attack_type=result.attack_type,
                    confidence=result.confidence,
                    model=result.model,
                    status="open",
                    features=alert_data["features"],
                    flow_id=flow_dict.get("flow_id", "")[:120],
                )
                session.add(alert_obj)
                session.commit()
            except Exception as db_err:
                session.rollback()
                logger.error("Failed to save live alert to DB: %s", db_err)
            finally:
                session.close()

            # 2. Push alert to SSE Subscribers & Recent Memory
            self._recent_alerts.append(alert_data)
            BROADCASTER.publish_event("alert", alert_data)

        except Exception as e:
            logger.error("Error evaluating completed flow: %s", e)

    def get_recent_packets(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._recent_packets)[-limit:]

    def get_recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._recent_alerts)[-limit:]


# Global singleton manager
TSHARK_MANAGER = TSharkCaptureManager()


def get_capture_manager() -> TSharkCaptureManager:
    return TSHARK_MANAGER
