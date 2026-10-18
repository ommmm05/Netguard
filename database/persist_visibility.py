"""Persist or restore visibility snapshots to SQLite."""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import delete
from sqlalchemy.orm import Session

from database.models import (
    ArpEntry,
    BandwidthBin,
    DhcpMeta,
    DNSStat,
    Flow,
    Host,
    HttpMeta,
    PcapUpload,
    TlsMeta,
)
from visibility.ingest_state import IngestSnapshot


def clear_visibility_rows(session: Session) -> None:
    """Remove visibility data (keeps pcap record rows for admin listing if desired)."""
    session.execute(delete(BandwidthBin))
    session.execute(delete(TlsMeta))
    session.execute(delete(HttpMeta))
    session.execute(delete(DhcpMeta))
    session.execute(delete(ArpEntry))
    session.execute(delete(DNSStat))
    session.execute(delete(Flow))
    session.execute(delete(Host))
    session.flush()


def store_snapshot(
    session: Session, snap: IngestSnapshot, pcap: PcapUpload | None
) -> None:
    clear_visibility_rows(session)
    pcap_id = pcap.id if pcap and getattr(pcap, "id", None) else None
    now = datetime.utcnow()

    for h in snap.hosts_as_list():
        ip = h["ip"]
        b = int(snap.hosts.get(ip, {}).get("bytes", 0) or 0)
        session.add(
            Host(
                ip=ip,
                mac=(snap.arp.get(ip) or snap.hosts[ip].get("mac") or None),
                hostname=h.get("hostname"),
                os_hint=h.get("os"),
                role=h.get("role"),
                open_ports=json.dumps(h.get("openPorts") or []),
                risk_score=int(h.get("riskScore", 0)),
                status=str(h.get("status", "active")),
                bytes_seen=b,
                last_seen=now,
                first_seen=now,
            )
        )
    for f in snap.flows.values():
        row = f.to_row()
        fid = str(row.get("flow_id", "x"))[:255]
        try:
            fs = datetime.fromisoformat(
                (row.get("startTime") or "1970-01-01T00:00:00Z").replace("Z", "+00:00")
            )
            fe = datetime.fromisoformat(
                (row.get("endTime") or "1970-01-01T00:00:00Z").replace("Z", "+00:00")
            )
        except Exception:
            fs, fe = now, now
        session.add(
            Flow(
                id=fid,
                src_ip=row["srcIp"],
                dst_ip=row["dstIp"],
                src_port=int(row.get("srcPort", 0)),
                dst_port=int(row.get("dstPort", 0)),
                protocol=str(row.get("protocol", "IP")),
                first_ts=fs,
                last_ts=fe,
                duration_s=float(row.get("duration", 0) or 0),
                packets=int(row.get("packets", 0) or 0),
                bytes_total=int(row.get("bytes", 0) or 0),
                state=row.get("state"),
                threat_hint=row.get("threat"),
                severity=str(row.get("severity", "info") or "info"),
                suspicious=bool(row.get("suspicious", False)),
                pcap_id=pcap_id,
            )
        )
    for _k, d in snap.dns.items():
        session.add(
            DNSStat(
                domain=d["domain"],
                query_type=str(d.get("queryType", "A")),
                count=int(d.get("count", 0)),
                first_seen=now,
                last_seen=now,
                sample_resolved=None
                if d.get("resolvedIp") in ("—", None, "")
                else str(d.get("resolvedIp")),
                category=d.get("category"),
                suspicious=bool(d.get("suspicious", False)),
            )
        )
    for ip, mac in snap.arp.items():
        confl = len({m.lower() for m in (snap.arp_macs.get(ip) or []) if m}) > 1
        session.add(
            ArpEntry(
                ip=ip,
                mac=mac,
                first_seen=now,
                entry_type="observed",
                suspicious=confl,
                pcap_id=pcap_id,
            )
        )
    for t in snap.tls:
        session.add(
            TlsMeta(
                src_ip=t["srcIp"],
                dst_ip=t["dstIp"],
                sni=t.get("sni"),
                version=t.get("version"),
                cipher=t.get("cipherSuite"),
                cert_issuer=t.get("certIssuer"),
                suspicious=bool(t.get("suspicious", False)),
                pcap_id=pcap_id,
            )
        )
    for h in snap.http_observations.values():
        session.add(
            HttpMeta(
                src_ip=str(h.get("srcIp", "")),
                dst_ip=str(h.get("dstIp", "")),
                host_header=str(h.get("hostHeader", ""))[:512],
                count=int(h.get("count", 1) or 1),
                first_seen=now,
                last_seen=now,
                pcap_id=pcap_id,
            )
        )
    for d in snap.dhcp_observations:
        session.add(
            DhcpMeta(
                client_ip=str(d.get("clientIp", "")),
                hostname=None if d.get("hostname") in (None, "—") else str(d.get("hostname"))[:256],
                server_ip=None if d.get("serverIp") in (None, "—") else str(d.get("serverIp"))[:45],
                first_seen=now,
                pcap_id=pcap_id,
            )
        )
    for label, b in snap.bwidth.items():
        tot = int((b.get("inbound", 0) or 0) + (b.get("outbound", 0) or 0))
        in_b = float(b.get("inbound", 0) or 0)
        out_b = float(b.get("outbound", 0) or 0)
        session.add(
            BandwidthBin(
                bucket_label=label,
                inbound_mbps=(in_b * 8.0) / 1_000_000.0,
                outbound_mbps=(out_b * 8.0) / 1_000_000.0,
                total_bytes=tot,
                pcap_id=pcap_id,
            )
        )
    session.flush()
