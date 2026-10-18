"""
utils/live_capture.py — Real-time connected user monitoring via Wireshark (tshark).

Runs tshark as a subprocess (-T ek mode), parses streaming JSON objects line by line,
and maintains thread-safe user activity metrics and risk scores.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Optional

# Locate tshark.exe
DEFAULT_TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
if os.path.exists(DEFAULT_TSHARK):
    TSHARK_PATH = DEFAULT_TSHARK
else:
    TSHARK_PATH = shutil.which("tshark") or "tshark"

# ── Shared state (thread-safe via lock) ───────────────────────────────────────
capture_state: dict[str, Any] = {
    "running": False,
    "users": {},        # keyed by src_ip -> user activity dict
    "packets_total": 0,
    "bytes_total": 0,
    "start_time": None,
    "error": None,
    "_proc": None,
}
_lock = threading.Lock()
_capture_thread: Optional[threading.Thread] = None


# ── Protocol detection from tshark frame ──────────────────────────────────────
PROTO_PRIORITY = [
    "http", "tls", "dns", "dhcp", "ssh", "ftp", "smtp",
    "modbus", "dnp3", "s7comm", "enip", "snmp",
    "icmp", "arp", "tcp", "udp"
]


def detect_protocol(layers: dict) -> str:
    for proto in PROTO_PRIORITY:
        if proto in layers:
            return proto.upper()
    return "OTHER"


# ── Parse one tshark JSON frame ───────────────────────────────────────────────
def parse_frame(frame: dict) -> dict | None:
    try:
        layers = frame.get("_source", {}).get("layers", {})
        if not layers and "layers" in frame:
            layers = frame["layers"]

        # IP layer
        ip = layers.get("ip", {})
        if isinstance(ip, list) and ip:
            ip = ip[0]
        src_ip = ip.get("ip_ip_src") or ip.get("ip.src", "")
        dst_ip = ip.get("ip_ip_dst") or ip.get("ip.dst", "")
        if isinstance(src_ip, list):
            src_ip = src_ip[0]
        if isinstance(dst_ip, list):
            dst_ip = dst_ip[0]

        if not src_ip or not dst_ip:
            return None  # skip non-IP

        # Ethernet / MAC
        eth = layers.get("eth", {})
        if isinstance(eth, list) and eth:
            eth = eth[0]
        src_mac = eth.get("eth_eth_src") or eth.get("eth.src", "")
        if isinstance(src_mac, list):
            src_mac = src_mac[0]

        # Size & Timestamp
        frame_info = layers.get("frame", {})
        if isinstance(frame_info, list) and frame_info:
            frame_info = frame_info[0]

        pkt_len_val = frame_info.get("frame_frame_len") or frame_info.get("frame.len", 0)
        if isinstance(pkt_len_val, list):
            pkt_len_val = pkt_len_val[0]
        pkt_len = int(pkt_len_val)

        ts_val = frame_info.get("frame_frame_time_epoch") or frame_info.get("frame.time_epoch", time.time())
        if isinstance(ts_val, list):
            ts_val = ts_val[0]
        timestamp = float(ts_val)

        # Ports
        tcp = layers.get("tcp", {})
        if isinstance(tcp, list) and tcp:
            tcp = tcp[0]
        udp = layers.get("udp", {})
        if isinstance(udp, list) and udp:
            udp = udp[0]

        dst_port_val = (
            tcp.get("tcp_tcp_dstport") or tcp.get("tcp.dstport") or
            udp.get("udp_udp_dstport") or udp.get("udp.dstport") or 0
        )
        if isinstance(dst_port_val, list):
            dst_port_val = dst_port_val[0]
        dst_port = int(dst_port_val)

        protocol = detect_protocol(layers)

        return {
            "src_ip": str(src_ip),
            "dst_ip": str(dst_ip),
            "src_mac": str(src_mac),
            "protocol": protocol,
            "dst_port": dst_port,
            "length": pkt_len,
            "timestamp": timestamp,
        }
    except Exception:
        return None


# ── Update shared user activity store ────────────────────────────────────────
def update_user_store(pkt: dict):
    src = pkt["src_ip"]
    with _lock:
        if src not in capture_state["users"]:
            capture_state["users"][src] = {
                "ip": src,
                "mac": pkt["src_mac"],
                "packets": 0,
                "bytes": 0,
                "protocols": defaultdict(int),
                "connections": set(),
                "last_seen": None,
                "first_seen": None,
                "risk_score": 0,
            }
        u = capture_state["users"][src]
        u["packets"] += 1
        u["bytes"] += pkt["length"]
        u["protocols"][pkt["protocol"]] += 1
        u["connections"].add(pkt["dst_ip"])
        formatted_ts = datetime.fromtimestamp(pkt["timestamp"]).strftime("%H:%M:%S")
        u["last_seen"] = formatted_ts
        if u["first_seen"] is None:
            u["first_seen"] = formatted_ts

        # Risk scoring logic
        risk = 0
        if len(u["connections"]) > 20:
            risk += 30  # many unique destinations
        if u["protocols"].get("MODBUS", 0) > 0 or u["protocols"].get("DNP3", 0) > 0:
            risk += 25  # OT protocol detected
        if u["protocols"].get("SSH", 0) > 50:
            risk += 20  # high SSH activity
        if u["bytes"] > 50_000_000:
            risk += 15  # >50 MB transferred
        if u["protocols"].get("DNS", 0) > 200:
            risk += 10  # DNS flood/tunneling risk
        u["risk_score"] = min(risk, 100)

        capture_state["packets_total"] += 1
        capture_state["bytes_total"] += pkt["length"]


def _reader_thread_ek(interface: str, bpf_filter: str):
    """
    Uses tshark -T ek which outputs one JSON object per line.
    """
    cmd = [
        TSHARK_PATH,
        "-i", str(interface),
        "-T", "ek",
        "-l",
    ]
    if bpf_filter and bpf_filter.strip():
        cmd.extend(bpf_filter.strip().split())

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        with _lock:
            capture_state["_proc"] = proc

        for raw_line in proc.stdout:
            with _lock:
                if not capture_state["running"]:
                    break
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "layers" not in obj and "_source" not in obj:
                continue

            pkt = parse_frame(obj)
            if pkt:
                update_user_store(pkt)

        proc.wait()
    except FileNotFoundError:
        with _lock:
            capture_state["error"] = (
                f"tshark.exe not found at {TSHARK_PATH}. Please install Wireshark."
            )
    except Exception as e:
        with _lock:
            capture_state["error"] = str(e)
    finally:
        with _lock:
            capture_state["running"] = False
            capture_state["_proc"] = None


# ── Public API ────────────────────────────────────────────────────────────────
def list_interfaces() -> list[str]:
    """Return interface names tshark can see."""
    try:
        result = subprocess.run(
            [TSHARK_PATH, "-D"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        lines = result.stdout.strip().split("\n")
        ifaces: list[str] = []
        for line in lines:
            parts = line.strip().split(" ", 1)
            if len(parts) == 2:
                ifaces.append(parts[1])
        return ifaces
    except Exception:
        return []


def start_capture(interface: str = "1", bpf_filter: str = "") -> bool:
    global _capture_thread
    with _lock:
        if capture_state["running"]:
            return False
        capture_state.update({
            "running": True,
            "users": {},
            "packets_total": 0,
            "bytes_total": 0,
            "start_time": datetime.now().strftime("%H:%M:%S"),
            "error": None,
            "_proc": None,
        })
    _capture_thread = threading.Thread(
        target=_reader_thread_ek,
        args=(interface, bpf_filter),
        daemon=True,
        name="tshark-live-capture",
    )
    _capture_thread.start()
    return True


def stop_capture():
    with _lock:
        capture_state["running"] = False
        proc = capture_state.get("_proc")
    if proc:
        try:
            proc.terminate()
        except Exception:
            pass


def get_snapshot() -> dict[str, Any]:
    """Thread-safe copy of current capture state for Dash callbacks."""
    with _lock:
        users_copy = {}
        for ip, u in capture_state["users"].items():
            top_proto = "–"
            if u["protocols"]:
                top_proto = max(u["protocols"], key=u["protocols"].get)
            users_copy[ip] = {
                "ip": u["ip"],
                "mac": u["mac"],
                "packets": u["packets"],
                "bytes": u["bytes"],
                "protocols": dict(u["protocols"]),
                "connections": len(u["connections"]),
                "first_seen": u["first_seen"],
                "last_seen": u["last_seen"],
                "risk_score": u["risk_score"],
                "top_protocol": top_proto,
            }
        return {
            "running": capture_state["running"],
            "users": users_copy,
            "packets_total": capture_state["packets_total"],
            "bytes_total": capture_state["bytes_total"],
            "start_time": capture_state["start_time"],
            "error": capture_state["error"],
        }
