"""
Accumulates parsed packet data into a snapshot suitable for API + DB export.
Scapy is used in capture/ to decode frames; this module is pure aggregation.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from visibility.flow_key import forward_tuple_from_packet, make_flow_id
from visibility.heuristics import dns_looks_suspicious, flow_threat_flags
from visibility.network_utils import is_displayable_ip, is_rfc1918, protocol_label


@dataclass
class FlowAgg:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    l4: str
    first_ts: float
    last_ts: float
    packets: int = 0
    bytes_total: int = 0
    bytes_to_dst: int = 0
    bytes_to_src: int = 0

    def to_row(self) -> dict[str, Any]:
        a_ip, a_port, b_ip, b_port, p = forward_tuple_from_packet(
            self.src_ip, self.dst_ip, self.src_port, self.dst_port, int(self.proto)
        )
        fid = make_flow_id(p, a_ip, a_port, b_ip, b_port)
        duration = max(0.0, self.last_ts - self.first_ts)
        if self.l4 == "TCP":
            ptype = "TCP"
        elif self.l4 == "UDP":
            ptype = "UDP"
        elif self.l4 == "ICMP":
            ptype = "ICMP"
        elif self.l4 == "ARP":
            ptype = "ARP"
        else:
            ptype = "IP"
        plab = protocol_label(ptype, self.dst_port, self.src_port)
        threat, severity, sus = flow_threat_flags(
            ptype, self.src_port, self.dst_port, duration, self.bytes_total, self.packets, self.src_ip, self.dst_ip
        )
        if plab in ("RDP", "SMB", "HTTP", "HTTPS", "HTTP/HTTPS", "TLS/HTTPS") and not threat:
            threat, severity, sus = None, "info", False
        if sus:
            if severity == "info":
                severity = "low"
        return {
            "id": f"f-{fid[:12]}",
            "flow_id": fid,
            "srcIp": self.src_ip,
            "dstIp": self.dst_ip,
            "srcPort": self.src_port,
            "dstPort": self.dst_port,
            "protocol": plab,
            "duration": round(duration, 2),
            "packets": self.packets,
            "bytes": int(self.bytes_total),
            "startTime": _iso(self.first_ts),
            "endTime": _iso(self.last_ts),
            "state": "ESTABLISHED" if self.packets > 2 else "SINGLE",  # passive guess
            "threat": threat,
            "severity": severity,
            "suspicious": sus,
        }


def _iso(ts: float) -> str:
    return datetime.utcfromtimestamp(ts).replace(microsecond=0).isoformat() + "Z"


@dataclass
class IngestSnapshot:
    started_at: float = 0.0
    ended_at: float = 0.0
    packet_count: int = 0
    # flow_id -> FlowAgg
    flows: dict[str, FlowAgg] = field(default_factory=dict)
    # host ip -> {mac, hostnames, ports set, bytes, first, last, protocols set}
    hosts: dict[str, dict[str, Any]] = field(default_factory=dict)
    proto_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # dns key qname|type
    dns: dict[str, dict[str, Any]] = field(default_factory=dict)
    # arp ip -> {mac, last}
    arp: dict[str, str] = field(default_factory=dict)
    arp_macs: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    # tls list
    tls: list[dict[str, Any]] = field(default_factory=list)
    tls_dedup: set[tuple[str, str]] = field(default_factory=set)
    # bandwidth bucket index -> in/out (bytes)
    bwidth: dict[str, dict[str, float]] = field(default_factory=dict)
    # per-host contact fan-out: ip -> set(strip others)
    fanout: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    # suspicious comms pattern messages
    pattern_events: list[dict[str, Any]] = field(default_factory=list)
    # HTTP Host: headers (passive, no bodies) — key src|dst|hostlower
    http_observations: dict[str, dict[str, Any]] = field(default_factory=dict)
    # DHCP rows (deduped by client|server)
    dhcp_observations: list[dict[str, Any]] = field(default_factory=list)
    _dhcp_keys: set[str] = field(default_factory=set)

    def _ensure_host(self, ip: str) -> None:
        if not ip:
            return
        if ip not in self.hosts:
            self.hosts[ip] = {
                "mac": None,
                "hostname": None,
                "ports": set(),
                "first_ts": self.started_at or 0,
                "last_ts": 0.0,
                "bytes": 0,
                "protocols": set(),
            }

    def add_l3_bytes(self, src: str, dst: str, nbytes: int, when: float) -> None:
        self._ensure_host(src)
        self._ensure_host(dst)
        self.hosts[src]["bytes"] = int(self.hosts[src].get("bytes", 0)) + nbytes
        self.hosts[dst]["bytes"] = int(self.hosts[dst].get("bytes", 0)) + nbytes
        for h in (src, dst):
            self.hosts[h]["last_ts"] = max(self.hosts[h].get("last_ts", 0.0), when)
            if self.started_at == 0:
                self.hosts[h]["first_ts"] = when
        self.fanout[src].add(dst)
        self.fanout[dst].add(src)

    def _bucket_key(self, when: float) -> str:
        t0 = self.started_at or when
        t1 = self.ended_at or when
        span = max(1.0, t1 - t0)
        # up to 24 slots
        n_slots = min(24, max(1, int(span / 300) or 1))  # ~5 min default min span
        slot = int((when - t0) / max(span / n_slots, 1e-6))
        slot = min(n_slots - 1, max(0, slot))
        hour = (slot * 24) // n_slots
        return f"{hour:02d}:00"

    def add_bucket_traffic(self, src: str, dst: str, nbytes: int, when: float) -> None:
        lab = self._bucket_key(when)
        if lab not in self.bwidth:
            self.bwidth[lab] = {"inbound": 0.0, "outbound": 0.0, "n": 0.0}
        # Passive approximation: "inbound" = toward RFC1918; "outbound" = from RFC1918
        if is_rfc1918(dst):
            self.bwidth[lab]["inbound"] += nbytes
        if is_rfc1918(src):
            self.bwidth[lab]["outbound"] += nbytes
        self.bwidth[lab]["n"] += 1.0

    def register_flow(
        self,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        proto: int,
        l4: str,
        pkt_len: int,
        when: float,
    ) -> None:
        fid = make_flow_id(proto, src, sport, dst, dport)
        if self.started_at == 0:
            self.started_at = when
        else:
            self.started_at = min(self.started_at, when)
        self.ended_at = max(self.ended_at, when)
        self.packet_count += 1
        pl = protocol_label("TCP" if l4 == "TCP" else "UDP" if l4 == "UDP" else l4, dport, sport)
        self.proto_counts[pl] = int(self.proto_counts.get(pl, 0)) + 1

        if fid not in self.flows:
            self.flows[fid] = FlowAgg(src, dst, sport, dport, proto, l4, when, when, 0, 0, 0, 0)
        f = self.flows[fid]
        f.packets += 1
        f.bytes_total += pkt_len
        f.last_ts = when
        f.first_ts = min(f.first_ts, when)
        if dst == f.dst_ip:
            f.bytes_to_dst += pkt_len
        else:
            f.bytes_to_src += pkt_len
        for ip, p in ((src, dport if src == f.src_ip else sport), (dst, sport if src == f.dst_ip else dport)):
            self._ensure_host(ip)
            self.hosts[ip]["ports"].add(int(p))
            self.hosts[ip]["protocols"].add(pl)
        self.add_l3_bytes(src, dst, pkt_len, when)
        self.add_bucket_traffic(src, dst, pkt_len, when)

    def register_dns(
        self, name: str, qtype: str, src_ip: str, answer: str | None, when: float
    ) -> None:
        if not name:
            return
        k = f"{name}|{qtype}"
        sus = dns_looks_suspicious(name)
        cat = "Malicious" if sus else "Benign"
        if k not in self.dns:
            self.dns[k] = {
                "domain": name.rstrip("."),
                "queryType": qtype,
                "count": 0,
                "firstSeen": _iso(when),
                "lastSeen": _iso(when),
                "resolvedIp": answer or "—",
                "suspicious": sus,
                "category": cat,
            }
        o = self.dns[k]
        o["count"] = int(o["count"]) + 1
        o["lastSeen"] = _iso(when)
        if answer:
            o["resolvedIp"] = answer
        o["suspicious"] = o["suspicious"] or sus
        o["category"] = cat
        self._ensure_host(src_ip)
        self.hosts[src_ip]["last_ts"] = max(self.hosts[src_ip].get("last_ts", 0.0), when)

    def register_arp(self, ip: str, mac: str, when: float) -> None:
        self.arp[ip] = mac
        self.arp_macs[ip].append(mac)
        self._ensure_host(ip)
        self.hosts[ip]["mac"] = mac
        self.hosts[ip]["last_ts"] = max(self.hosts[ip].get("last_ts", 0.0), when)
        if not self.hosts[ip].get("first_ts"):
            self.hosts[ip]["first_ts"] = when

    def register_tls(
        self,
        src: str,
        dst: str,
        sni: str | None,
        version: str | None,
        cipher: str | None,
        issuer: str | None,
    ) -> None:
        k = (src, dst)
        if k in self.tls_dedup:
            return
        self.tls_dedup.add(k)
        self_su = (issuer and "self" in str(issuer).lower()) or (issuer in ("", None, "—"))
        sus = bool(self_su or (sni in ("", None, "none", "—")))
        self.tls.append(
            {
                "srcIp": src,
                "dstIp": dst,
                "sni": sni or "none",
                "version": version or "—",
                "cipherSuite": cipher or "—",
                "certIssuer": issuer or ("Self-Signed" if self_su else "—"),
                "suspicious": sus,
            }
        )

    def register_http_host(self, src: str, dst: str, host: str, when: float) -> None:
        if not host:
            return
        self._ensure_host(src)
        self._ensure_host(dst)
        hname = host.split(":", 1)[0].strip()[:200]
        if not self.hosts[dst].get("hostname"):
            self.hosts[dst]["hostname"] = hname
        for ip in (src, dst):
            self._ensure_host(ip)
            self.hosts[ip]["last_ts"] = max(self.hosts[ip].get("last_ts", 0.0), when)
        key = f"{src}|{dst}|{hname.lower()}"
        row = self.http_observations.get(key)
        if not row:
            self.http_observations[key] = {
                "srcIp": src,
                "dstIp": dst,
                "hostHeader": hname,
                "count": 1,
                "firstSeen": _iso(when),
                "lastSeen": _iso(when),
            }
        else:
            row["count"] = int(row["count"]) + 1
            row["lastSeen"] = _iso(when)

    def register_dhcp_observation(
        self, client_ip: str, hostname: str | None, server_ip: str, when: float
    ) -> None:
        if not client_ip or client_ip == "0.0.0.0":
            return
        k = f"{client_ip}|{server_ip}"
        if k in self._dhcp_keys:
            return
        self._dhcp_keys.add(k)
        self.dhcp_observations.append(
            {
                "clientIp": client_ip,
                "hostname": hostname or "—",
                "serverIp": server_ip or "—",
                "seenAt": _iso(when),
            }
        )

    def run_pattern_hooks(self) -> None:
        """After ingest, derive extra suspicious patterns (fan-out, ARP)."""
        for ip, others in self.fanout.items():
            if len(others) > 40:
                self.pattern_events.append(
                    {
                        "type": "high_fanout",
                        "ip": ip,
                        "peers": len(others),
                        "message": f"Host {ip} observed communicating with {len(others)} unique peers in capture window (possible scan or C2).",
                    }
                )
        # ARP same IP multiple MACs
        for ip, macs in self.arp_macs.items():
            um = {m.lower() for m in macs if m}
            if len(um) > 1:
                self.pattern_events.append(
                    {
                        "type": "arp_conflict",
                        "ip": ip,
                        "message": f"IP {ip} associated with {len(um)} different MACs — possible ARP spoofing or duplicate use.",
                    }
                )

    def _risk_score(self, ip: str) -> int:
        h = self.hosts.get(ip, {})
        score = 10
        ps = h.get("ports") or set()
        if {4444, 1337, 31337, 6667, 9001} & set(ps):
            score += 35
        if len(self.fanout.get(ip, set())) > 30:
            score += 20
        for ev in self.pattern_events:
            if ev.get("ip") == ip or ip in (ev.get("message") or ""):
                score += 15
        for d in self.dns.values():
            if d.get("suspicious") and d.get("domain"):
                # rough: if this host in flows to dns? skip cross-link; small bump
                pass
        return min(100, score)

    def hosts_as_list(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        idx = 0
        for ip, h in self.hosts.items():
            if not is_displayable_ip(ip):
                continue
            idx += 1
            mac = h.get("mac") or "—"
            name = h.get("hostname") or f"host-{idx}"
            ports = sorted(h.get("ports") or set())
            role = h.get("device_type") or h.get("role") or "Unknown"
            if role == "Unknown":
                if 502 in ports or 20000 in ports or 44818 in ports or 102 in ports:
                    role = "PLC/OT"
                elif 53 in ports or 67 in ports:
                    role = "Gateway"
                elif 22 in ports and (80 in ports or 443 in ports):
                    role = "Server"
                elif 3389 in ports or 445 in ports:
                    role = "Workstation"
                elif 80 in ports or 443 in ports or 8080 in ports:
                    role = "Server"
            os_label = h.get("os") or (
                "Unknown" if h.get("hostname") is None else "Inferred from traffic"
            )
            st = "active" if h.get("last_ts", 0) >= (self.ended_at - 3600) else "stale"
            if self._risk_score(ip) > 70:
                st = "suspicious" if st == "active" else st
            out.append(
                {
                    "id": f"h{idx}",
                    "ip": ip,
                    "mac": mac,
                    "hostname": name,
                    "os": os_label,
                    "role": role,
                    "deviceType": role,
                    "openPorts": ports[:20],
                    "lastSeen": _iso(h.get("last_ts") or self.ended_at or self.started_at),
                    "riskScore": self._risk_score(ip),
                    "status": st,
                }
            )
        return sorted(out, key=lambda x: x["ip"])

    def top_talkers(self) -> list[dict[str, Any]]:
        items = []
        for ip, h in self.hosts.items():
            items.append((int(h.get("bytes", 0)), ip, h.get("hostname") or "—"))
        items.sort(reverse=True, key=lambda x: x[0])
        if not items:
            return []
        topb = max(1, items[0][0])
        res = []
        for rank, (b, ip, name) in enumerate(items[:8], 1):
            res.append(
                {
                    "rank": rank,
                    "ip": ip,
                    "hostname": name,
                    "totalBytes": b,
                    "pctOfTotal": round(100.0 * b / topb, 1),
                    "role": "—",
                }
            )
        return res

    def protocol_distribution(self) -> list[dict[str, Any]]:
        total = max(1, sum(self.proto_counts.values()))
        out = []
        for name, c in sorted(self.proto_counts.items(), key=lambda x: -x[1])[:10]:
            out.append(
                {
                    "protocol": name,
                    "count": c,
                    "percentage": round(100.0 * c / total, 1),
                }
            )
        return out

    def bandwidth_series(self) -> list[dict[str, Any]]:
        """Normalize buckets to a chart-friendly series; Mbps = bytes *8 / 60? rough"""
        if not self.bwidth:
            return []
        keys = sorted(self.bwidth.keys(), key=lambda k: k)
        res = []
        for label in keys:
            v = self.bwidth[label]
            # display as Mb/s with arbitrary scale: assume 60s per bucket
            sec = max(1.0, (self.ended_at - self.started_at) / max(1, len(keys)))
            in_mbps = (v["inbound"] * 8) / 1_000_000 / max(1, sec * 0.1)
            out_mbps = (v["outbound"] * 8) / 1_000_000 / max(1, sec * 0.1)
            res.append(
                {
                    "time": label,
                    "inbound": round(in_mbps, 2),
                    "outbound": round(out_mbps, 2),
                }
            )
        return res

    def comm_edges(self) -> list[dict[str, Any]]:
        edges: list[dict[str, Any]] = []
        for f in self.flows.values():
            row = f.to_row()
            src, dst = row["srcIp"], row["dstIp"]
            if not is_displayable_ip(src) or not is_displayable_ip(dst):
                continue
            edges.append(
                {
                    "source": src,
                    "target": dst,
                    "bytes": row["bytes"],
                    "protocol": row["protocol"],
                    "suspicious": bool(row.get("suspicious")),
                }
            )
        return edges

    def comm_nodes(self) -> list[dict[str, Any]]:
        nodes: list[dict[str, Any]] = []
        for h in self.hosts_as_list():
            ip = h["ip"]
            if not is_displayable_ip(ip):
                continue
            lab = h.get("hostname") or ip
            if isinstance(lab, str) and len(lab) > 12:
                lab = lab[:12] + "…"
            nodes.append(
                {
                    "id": ip,
                    "ip": ip,
                    "label": str(lab),
                    "risk": h["riskScore"],
                    "deviceType": h.get("deviceType") or h.get("role") or "Unknown",
                }
            )
        return nodes
