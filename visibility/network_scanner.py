"""
Live LAN discovery: subnet detect → ARP sweep (Scapy) → fast nmap per host.

Runs in a background thread; poll `get_scan_state()` for progressive UI updates.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from copy import deepcopy
from typing import Any, Optional

from visibility.device_classifier import classify_device
from visibility.ingest_state import IngestSnapshot
from visibility.network_utils import is_displayable_ip
from visibility.service import get_visibility_service

logger = logging.getLogger(__name__)

_lock = threading.RLock()
_scan_state: dict[str, Any] = {
    "status": "idle",  # idle | scanning | done | error
    "hosts": [],
    "progress": 0,
    "subnet": None,
    "local_ip": None,
    "gateway_ip": None,
    "error": None,
    "message": None,
    "started_at": None,
    "finished_at": None,
}
_worker: Optional[threading.Thread] = None


def get_scan_state() -> dict[str, Any]:
    with _lock:
        return deepcopy(_scan_state)


def _set_state(**kwargs: Any) -> None:
    with _lock:
        _scan_state.update(kwargs)


def get_local_subnet() -> tuple[str, str, Optional[str]]:
    """
    Return (subnet_cidr, local_ip, gateway_ip).
    Tries netifaces, then Scapy routing table, then UDP connect + /24 guess.
    """
    # 1) netifaces (optional)
    try:
        import netifaces  # type: ignore

        gws = netifaces.gateways()
        default = gws.get("default", {}).get(netifaces.AF_INET)
        if default:
            gw_ip, iface = default[0], default[1]
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            if addrs:
                ip = addrs[0]["addr"]
                mask = addrs[0].get("netmask") or "255.255.255.0"
                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                return str(network), ip, str(gw_ip)
    except Exception as e:  # noqa: BLE001
        logger.debug("netifaces subnet detect failed: %s", e)

    # 2) Scapy route
    try:
        from scapy.all import conf  # noqa: WPS433

        # route("0.0.0.0") → (network, netmask, gw, iface, output_ip)
        _net, netmask, gw, _iface, out_ip = conf.route.route("0.0.0.0")
        if out_ip and out_ip != "0.0.0.0":
            mask = netmask if isinstance(netmask, str) else "255.255.255.0"
            if isinstance(netmask, int):
                # scapy sometimes returns packed int
                mask = str(ipaddress.IPv4Address(netmask))
            try:
                network = ipaddress.IPv4Network(f"{out_ip}/{mask}", strict=False)
            except ValueError:
                network = ipaddress.IPv4Network(f"{out_ip}/24", strict=False)
            gw_s = str(gw) if gw and str(gw) != "0.0.0.0" else None
            return str(network), str(out_ip), gw_s
    except Exception as e:  # noqa: BLE001
        logger.debug("scapy route subnet detect failed: %s", e)

    # 3) UDP connect trick + /24
    ip = _local_ip_via_udp()
    network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
    return str(network), ip, None


def _local_ip_via_udp() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def arp_scan(subnet: str, timeout: float = 2.0) -> list[dict[str, str]]:
    """Non-intrusive ARP sweep; requires Npcap (Windows) or root/CAP_NET_RAW (Linux)."""
    from scapy.all import ARP, Ether, srp  # noqa: WPS433

    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result, _ = srp(packet, timeout=timeout, verbose=False)
    hosts: list[dict[str, str]] = []
    seen: set[str] = set()
    for _sent, received in result:
        ip = str(received.psrc)
        mac = str(received.hwsrc)
        if ip in seen or not is_displayable_ip(ip):
            continue
        seen.add(ip)
        hosts.append({"ip": ip, "mac": mac})
    return hosts


def scan_host(ip: str) -> dict[str, Any]:
    """Quick nmap fast scan (top ports). Falls back gracefully if nmap is missing."""
    info: dict[str, Any] = {
        "ip": ip,
        "ports": [],
        "hostname": "",
        "os_guess": "Unknown",
    }
    try:
        import nmap  # type: ignore
    except ImportError:
        info["os_guess"] = "nmap unavailable"
        return info

    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-T4 -F --open")
    except Exception as e:  # noqa: BLE001
        logger.warning("nmap scan failed for %s: %s", ip, e)
        info["os_guess"] = f"nmap error: {e}"
        return info

    if ip not in nm.all_hosts():
        return info

    h = nm[ip]
    try:
        info["hostname"] = h.hostname() or ""
    except Exception:  # noqa: BLE001
        info["hostname"] = ""

    for proto in h.all_protocols():
        for port in h[proto].keys():
            svc = h[proto][port]
            info["ports"].append(
                {
                    "port": int(port),
                    "proto": proto,
                    "service": svc.get("name", ""),
                    "state": svc.get("state", ""),
                }
            )
    return info


def build_cytoscape_elements(
    hosts: list[dict[str, Any]],
    gateway_ip: str | None = None,
    local_ip: str | None = None,
) -> list[dict[str, Any]]:
    """Node/edge list suitable for dash-cytoscape or the React graph consumer."""
    elements: list[dict[str, Any]] = []
    gw = gateway_ip
    if not gw and hosts:
        # Prefer an explicit Gateway-classified host, else local_ip
        for h in hosts:
            if h.get("device_type") == "Gateway":
                gw = h["ip"]
                break
        if not gw:
            gw = local_ip

    node_ids: set[str] = set()
    for h in hosts:
        ip = h.get("ip")
        if not ip or not is_displayable_ip(ip):
            continue
        dtype = h.get("device_type") or "Unknown"
        hostname = h.get("hostname") or ""
        label = f"{ip}\n{dtype}" + (f"\n{hostname}" if hostname else "")
        elements.append(
            {
                "data": {
                    "id": ip,
                    "label": label,
                    "device_type": dtype,
                    "mac": h.get("mac") or "",
                    "hostname": hostname,
                    "ports": h.get("ports") or [],
                }
            }
        )
        node_ids.add(ip)

    if gw and gw not in node_ids and is_displayable_ip(gw):
        elements.append(
            {
                "data": {
                    "id": gw,
                    "label": f"{gw}\nGateway",
                    "device_type": "Gateway",
                    "mac": "",
                    "hostname": "gateway",
                    "ports": [],
                }
            }
        )
        node_ids.add(gw)

    if gw:
        for h in hosts:
            ip = h.get("ip")
            if not ip or ip == gw or ip not in node_ids:
                continue
            elements.append(
                {
                    "data": {
                        "id": f"{ip}-{gw}",
                        "source": ip,
                        "target": gw,
                        "protocol": "ARP",
                    }
                }
            )
    return elements


def _apply_hosts_to_visibility(
    hosts: list[dict[str, Any]],
    gateway_ip: str | None,
    local_ip: str | None,
) -> None:
    """Push discovered hosts into the live visibility snapshot (real data only)."""
    snap = IngestSnapshot()
    now = time.time()
    snap.started_at = now
    snap.ended_at = now

    seen_ips: set[str] = set()
    for h in hosts:
        ip = h.get("ip")
        if not ip or not is_displayable_ip(ip):
            continue
        seen_ips.add(ip)
        mac = h.get("mac") or ""
        if mac and mac != "—":
            snap.register_arp(ip, mac, now)
        else:
            snap._ensure_host(ip)
        host = snap.hosts[ip]
        if h.get("hostname"):
            host["hostname"] = h["hostname"]
        ports = {int(p["port"]) for p in (h.get("ports") or []) if p.get("port") is not None}
        host["ports"] = ports
        host["device_type"] = h.get("device_type") or "Unknown"
        host["role"] = h.get("device_type") or "Unknown"
        host["os"] = h.get("os_guess") or "Unknown"
        host["last_ts"] = now
        host["first_ts"] = now
        # Synthetic link to gateway so the comms graph is populated
        if gateway_ip and gateway_ip != ip and is_displayable_ip(gateway_ip):
            snap.register_flow(ip, gateway_ip, 0, 0, 0, "ARP", 64, now)

    if gateway_ip and is_displayable_ip(gateway_ip):
        snap._ensure_host(gateway_ip)
        g = snap.hosts[gateway_ip]
        g["device_type"] = "Gateway"
        g["role"] = "Gateway"
        if not g.get("hostname"):
            g["hostname"] = "gateway"
        g["last_ts"] = now

    if local_ip and is_displayable_ip(local_ip) and local_ip not in snap.hosts:
        snap._ensure_host(local_ip)
        snap.hosts[local_ip]["hostname"] = "this-host"
        snap.hosts[local_ip]["device_type"] = snap.hosts[local_ip].get("device_type") or "Workstation"
        snap.hosts[local_ip]["role"] = snap.hosts[local_ip].get("role") or "Workstation"
        snap.hosts[local_ip]["last_ts"] = now

    snap.packet_count = max(1, len(hosts))
    get_visibility_service().replace_snapshot(snap, "scan", None)


def run_scan_background(subnet: str, local_ip: str, gateway_ip: str | None = None) -> None:
    _set_state(
        status="scanning",
        hosts=[],
        progress=0,
        subnet=subnet,
        local_ip=local_ip,
        gateway_ip=gateway_ip,
        error=None,
        message=f"ARP sweeping {subnet}…",
        started_at=time.time(),
        finished_at=None,
    )
    try:
        try:
            hosts_arp = arp_scan(subnet)
        except Exception as e:  # noqa: BLE001
            logger.exception("ARP scan failed")
            _set_state(
                status="error",
                error=str(e),
                message=(
                    "ARP scan failed. On Windows install Npcap and run the backend as Administrator; "
                    "on Linux use root or CAP_NET_RAW."
                ),
                progress=0,
                finished_at=time.time(),
            )
            return

        if not hosts_arp:
            # Always include local host so the UI is not empty
            hosts_arp = [{"ip": local_ip, "mac": ""}]
            _set_state(message="No ARP replies; showing local IP only. Check Npcap/permissions.")

        total = len(hosts_arp)
        collected: list[dict[str, Any]] = []
        for i, host in enumerate(hosts_arp):
            detail = scan_host(host["ip"])
            detail["mac"] = host.get("mac") or ""
            detail["is_gateway"] = bool(gateway_ip and host["ip"] == gateway_ip)
            detail["device_type"] = classify_device(detail)
            collected.append(detail)
            progress = int((i + 1) / max(1, total) * 100)
            _set_state(
                hosts=list(collected),
                progress=progress,
                message=f"Scanned {host['ip']} ({i + 1}/{total})",
            )
            _apply_hosts_to_visibility(collected, gateway_ip, local_ip)

        # Ensure gateway is classified even if ARP missed it
        if gateway_ip and is_displayable_ip(gateway_ip):
            if not any(h["ip"] == gateway_ip for h in collected):
                gw_detail = {
                    "ip": gateway_ip,
                    "mac": "",
                    "ports": [],
                    "hostname": "gateway",
                    "os_guess": "Unknown",
                    "is_gateway": True,
                }
                gw_detail["device_type"] = "Gateway"
                collected.append(gw_detail)

        _apply_hosts_to_visibility(collected, gateway_ip, local_ip)
        _set_state(
            status="done",
            hosts=collected,
            progress=100,
            message=f"Done — {len(collected)} host(s)",
            finished_at=time.time(),
        )
    except Exception as e:  # noqa: BLE001
        logger.exception("Background scan crashed")
        _set_state(status="error", error=str(e), message=str(e), finished_at=time.time())


def start_network_scan() -> dict[str, Any]:
    """Start a background LAN scan if idle/done/error. Returns current state."""
    global _worker
    with _lock:
        if _scan_state.get("status") == "scanning" and _worker and _worker.is_alive():
            return deepcopy(_scan_state)

    try:
        subnet, local_ip, gateway_ip = get_local_subnet()
    except Exception as e:  # noqa: BLE001
        _set_state(status="error", error=str(e), message="Failed to detect local subnet")
        return get_scan_state()

    if local_ip.startswith("127."):
        _set_state(
            status="error",
            error="No usable LAN interface",
            message="Could not detect a non-loopback local IP. Connect to a network and retry.",
        )
        return get_scan_state()

    t = threading.Thread(
        target=run_scan_background,
        args=(subnet, local_ip, gateway_ip),
        daemon=True,
        name="netguard-lan-scan",
    )
    _worker = t
    t.start()
    return get_scan_state()
