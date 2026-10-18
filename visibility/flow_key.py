"""Canonical bidirectional 5-tuple for flow tracking."""

from __future__ import annotations


def make_flow_id(proto: int, a_ip: str, a_port: int, b_ip: str, b_port: int) -> str:
    """Return stable flow id: endpoints sorted so (A<->B) == (B<->A)."""
    t1 = (a_ip, a_port, b_ip, b_port, proto)
    t2 = (b_ip, b_port, a_ip, a_port, proto)
    use = t1 if t1 <= t2 else t2
    return f"{use[0]}|{use[1]}|{use[2]}|{use[3]}|{use[4]}"


def forward_tuple_from_packet(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int
) -> tuple[str, int, str, int, int]:
    """Return (a_ip, a_port, b_ip, b_port, proto) in canonical (sorted) form."""
    t1 = (src_ip, src_port, dst_ip, dst_port, proto)
    t2 = (dst_ip, dst_port, src_ip, src_port, proto)
    a_ip, a_port, b_ip, b_port, p = t1 if t1 <= t2 else t2
    return a_ip, a_port, b_ip, b_port, p
