"""Port / service / MAC heuristics for device type classification."""

from __future__ import annotations

from typing import Any


# Common OUI prefixes (lowercase, no separators) → vendor hint
_OUI_HINTS: dict[str, str] = {
    "00155d": "Microsoft",
    "000c29": "VMware",
    "005056": "VMware",
    "080027": "VirtualBox",
    "525400": "QEMU",
    "b8e856": "Apple",
    "acbc32": "Apple",
    "f0d1a9": "Apple",
    "3c22fb": "Apple",
    "dc4427": "Cisco",
    "00e0fc": "Huawei",
    "001a11": "Google",
    "b827eb": "Raspberry Pi",
    "dca632": "Raspberry Pi",
    "e45f01": "Raspberry Pi",
}


def _normalize_mac(mac: str | None) -> str:
    if not mac:
        return ""
    return "".join(c for c in mac.lower() if c.isalnum())


def oui_vendor(mac: str | None) -> str | None:
    m = _normalize_mac(mac)
    if len(m) < 6:
        return None
    return _OUI_HINTS.get(m[:6])


def classify_device(info: dict[str, Any]) -> str:
    """
    Classify device type from open ports, services, and optional MAC OUI.
    Returns one of: Gateway, PLC/OT, Server, Workstation, IoT/Sensor, Unknown
    """
    if info.get("is_gateway"):
        return "Gateway"

    ports = [int(p.get("port", 0)) for p in (info.get("ports") or []) if p.get("port") is not None]
    services = [str(p.get("service") or "").lower() for p in (info.get("ports") or [])]
    mac = info.get("mac")

    if 502 in ports or 20000 in ports or 44818 in ports or 102 in ports:
        return "PLC/OT"

    if any(s in ("modbus", "dnp", "enip", "s7comm", "bacnet") for s in services):
        return "PLC/OT"

    if 22 in ports and (80 in ports or 443 in ports):
        return "Server"

    if 3389 in ports or 445 in ports or 139 in ports:
        return "Workstation"

    httpish = any(s in ("http", "https", "www") for s in services) or (80 in ports or 443 in ports)
    if httpish and len(ports) < 5:
        return "IoT/Sensor"

    vendor = oui_vendor(mac)
    if vendor == "Raspberry Pi":
        return "IoT/Sensor"
    if vendor in ("Apple",) and not ports:
        return "Workstation"

    if 53 in ports or 67 in ports or 161 in ports:
        return "Gateway"

    if not ports:
        return "Unknown"
    return "Unknown"
