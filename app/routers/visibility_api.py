"""REST API for the Network Visibility module (Phase 1)."""

from __future__ import annotations

from fastapi import APIRouter

from visibility.service import get_visibility_service

router = APIRouter(prefix="/visibility", tags=["visibility"])


@router.get("/summary")
def summary() -> dict:
    snap = get_visibility_service().get_snapshot()
    h = snap.hosts_as_list()
    sus = [x for x in h if int(x.get("riskScore", 0)) > 70]
    protocols = sorted({str(k) for k in snap.proto_counts.keys()})
    talkers = snap.top_talkers()
    return {
        "discoveredHostCount": len(h),
        "suspiciousHostCount": len(sus),
        "activeSessionCount": len(snap.flows),
        "dnsQueryTotal": int(sum((d.get("count") or 0) for d in snap.dns.values()) or 0),
        "dnsSuspicious": len([1 for d in snap.dns.values() if d.get("suspicious")]),
        "packetCount": snap.packet_count,
        "protocolsSeen": protocols,
        "topTalker": talkers[0]["ip"] if talkers else None,
        "source": get_visibility_service().source_label,
    }


@router.get("/hosts")
def hosts() -> dict:
    return {"hosts": get_visibility_service().get_snapshot().hosts_as_list()}


@router.get("/flows")
def flows() -> dict:
    snap = get_visibility_service().get_snapshot()
    rows = [f.to_row() for f in snap.flows.values()]
    rows.sort(key=lambda r: (r.get("bytes") or 0), reverse=True)
    return {"flows": rows[:500]}


@router.get("/graph")
def graph() -> dict:
    snap = get_visibility_service().get_snapshot()
    return {"nodes": snap.comm_nodes(), "edges": snap.comm_edges()[:200]}


@router.get("/top-talkers")
def top_talkers() -> dict:
    return {"items": get_visibility_service().get_snapshot().top_talkers()}


@router.get("/protocols")
def protocols() -> dict:
    return {"items": get_visibility_service().get_snapshot().protocol_distribution()}


@router.get("/bandwidth")
def bandwidth() -> dict:
    return {"series": get_visibility_service().get_snapshot().bandwidth_series()}


@router.get("/dns")
def dns() -> dict:
    d = get_visibility_service().get_snapshot().dns
    return {"queries": list(d.values())}


@router.get("/l7-passive")
def l7_passive() -> dict:
    """Passive HTTP Host headers + DHCP observations (Phase 1 blueprint)."""
    snap = get_visibility_service().get_snapshot()
    return {
        "http": list(snap.http_observations.values()),
        "dhcp": list(snap.dhcp_observations),
    }


@router.get("/arp-tls")
def arp_tls() -> dict:
    snap = get_visibility_service().get_snapshot()
    arp = []
    for ip, mac in snap.arp.items():
        confl = len({m.lower() for m in (snap.arp_macs.get(ip) or []) if m}) > 1
        arp.append(
            {
                "ip": ip,
                "mac": mac,
                "type": "dynamic",
                "ttl": None,
                "suspicious": confl,
            }
        )
    return {"arp": arp, "tls": snap.tls}


@router.get("/patterns")
def patterns() -> dict:
    return {"events": get_visibility_service().get_snapshot().pattern_events}
