"""SQLAlchemy models for NetGuard (visibility, detection, forensics)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    BigInteger,
    Boolean,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.utcnow()


class Host(Base):
    __tablename__ = "hosts"

    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    mac: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    os_hint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    role: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    open_ports: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)  # JSON array as string
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="active")
    bytes_seen: Mapped[int] = mapped_column(BigInteger, default=0)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    extra: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)


class Flow(Base):
    __tablename__ = "flows"

    id: Mapped[str] = mapped_column(String(256), primary_key=True)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16))
    first_ts: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_ts: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_s: Mapped[float] = mapped_column(Float, default=0.0)
    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes_total: Mapped[int] = mapped_column(BigInteger, default=0)
    state: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    threat_hint: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    severity: Mapped[str] = mapped_column(String(32), default="info")
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    pcap_id: Mapped[Optional[int]] = mapped_column(ForeignKey("pcap_uploads.id"), nullable=True)


class DNSStat(Base):
    __tablename__ = "dns_stats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(512), index=True)
    query_type: Mapped[str] = mapped_column(String(8), default="A")
    count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sample_resolved: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False)


class ArpEntry(Base):
    __tablename__ = "arp_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    mac: Mapped[str] = mapped_column(String(17))
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    entry_type: Mapped[str] = mapped_column(String(32), default="observed")
    ttl: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    pcap_id: Mapped[Optional[int]] = mapped_column(ForeignKey("pcap_uploads.id"), nullable=True)


class TlsMeta(Base):
    __tablename__ = "tls_meta"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    sni: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    cipher: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    cert_issuer: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    pcap_id: Mapped[Optional[int]] = mapped_column(ForeignKey("pcap_uploads.id"), nullable=True)


class HttpMeta(Base):
    """Passive HTTP `Host:` header observations (no request bodies). Phase 1."""

    __tablename__ = "http_meta"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    host_header: Mapped[str] = mapped_column(String(512), index=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    pcap_id: Mapped[Optional[int]] = mapped_column(ForeignKey("pcap_uploads.id"), nullable=True)


class DhcpMeta(Base):
    """Passive DHCP option summaries (hostname / requested IP). Phase 1."""

    __tablename__ = "dhcp_meta"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_ip: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    server_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    pcap_id: Mapped[Optional[int]] = mapped_column(ForeignKey("pcap_uploads.id"), nullable=True)


class PcapUpload(Base):
    __tablename__ = "pcap_uploads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    original_name: Mapped[str] = mapped_column(String(512))
    stored_path: Mapped[str] = mapped_column(String(1024))
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    source: Mapped[str] = mapped_column(String(32), default="upload")  # upload | live


class BandwidthBin(Base):
    __tablename__ = "bandwidth_bins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    bucket_label: Mapped[str] = mapped_column(String(32), index=True)
    inbound_mbps: Mapped[float] = mapped_column(Float, default=0.0)
    outbound_mbps: Mapped[float] = mapped_column(Float, default=0.0)
    total_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    pcap_id: Mapped[Optional[int]] = mapped_column(ForeignKey("pcap_uploads.id"), nullable=True)


class MLAlert(Base):
    __tablename__ = "ml_alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    severity: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    attack_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    model: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")
    features: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    shap_top: Mapped[Optional[list[Any]]] = mapped_column(JSON, nullable=True)
    flow_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True, index=True)


class ForensicReport(Base):
    __tablename__ = "forensic_reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("ml_alerts.id"), nullable=True)
    summary_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    timeline: Mapped[Optional[list[Any]]] = mapped_column(JSON, nullable=True)
    shap_plot_base64: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
