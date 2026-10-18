"""
app.py — NetGuard Plotly Dash Entrypoint.

Registers the Phase 1 Network Visibility layout (PCAP Upload, Live Network Scanning, Live tshark User Monitoring)
and enforces Windows UAC elevation checks when necessary.
"""

from __future__ import annotations

import ctypes
import os
import sys

import dash

from phases.phase1_visibility import phase1_layout


def check_windows_admin() -> bool:
    """Check if process has Windows Administrator privileges for raw interface packet sniffing."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return True


if __name__ == "__main__":
    if not check_windows_admin():
        print("\n" + "=" * 70)
        print("⚠ WARNING: NetGuard Live Network Capture & ARP Scanning requires Administrator privileges.")
        print("  Please restart your command prompt or PowerShell as 'Run as Administrator'.")
        print("=" * 70 + "\n")

    app = dash.Dash(
        __name__,
        title="NetGuard — Network Visibility & Forensic Platform",
        suppress_callback_exceptions=True,
    )

    app.layout = phase1_layout()

    print("Starting NetGuard SOC Dashboard on http://127.0.0.1:8050 ...")
    app.run(debug=True, port=8050)
