"""
Generate a minimal PCAP for viva/demo when no capture hardware is available.
"""

from __future__ import annotations

from pathlib import Path

SAMPLE_NAME = "demo.pcap"


def sample_pcap_path(root: Path | None = None) -> Path:
    r = root or Path(__file__).resolve().parents[1]
    d = r / "data" / "sample"
    d.mkdir(parents=True, exist_ok=True)
    return d / SAMPLE_NAME


def write_demo_pcap(out: Path | None = None) -> Path:
    """Write a few IPv4 frames (ARP, DNS, TCP SYN to 443) for passive pipeline smoke tests."""
    out = out or sample_pcap_path()
    from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap

    pkts = []
    pkts.append(Ether() / ARP(psrc="192.168.1.10", pdst="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01", hwdst="ff:ff:ff:ff:ff:ff", op=1))
    pkts.append(
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=54321, dport=53)
        / DNS(qd=DNSQR(qname=b"google.com."))
    )
    pkts.append(Ether() / IP(src="192.168.1.10", dst="142.250.80.78") / TCP(sport=52000, dport=443, flags="S"))
    pkts.append(Ether() / IP(src="10.0.0.5", dst="192.168.1.10") / TCP(sport=40000, dport=3389, flags="S"))
    wrpcap(str(out), pkts)
    return out
