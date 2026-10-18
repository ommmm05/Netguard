"""
phases/phase1_visibility.py — Phase 1 Network Visibility Dashboard Layout & Callbacks.

Combines PCAP File Upload & Parsing, Active LAN Network Scanning, and Real-Time tshark Live User Monitoring.
"""

from __future__ import annotations

import dash_cytoscape as cyto
from dash import Input, Output, State, callback, ctx, dcc, html, dash_table
import plotly.graph_objects as go

from utils.device_classifier import classify_device
from utils.live_capture import get_snapshot, list_interfaces, start_capture, stop_capture
from utils.network_scanner import get_local_subnet, get_scan_state, start_network_scan
from utils.pcap_parser import parse_pcap_contents


def format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    if b < 1_048_576:
        return f"{b / 1024:.1f} KB"
    if b < 1_073_741_824:
        return f"{b / 1_048_576:.1f} MB"
    return f"{b / 1_073_741_824:.2f} GB"


CYTO_STYLESHEET = [
    {
        "selector": "node",
        "style": {
            "label": "data(label)",
            "text-wrap": "wrap",
            "font-size": "10px",
            "text-valign": "bottom",
            "background-color": "#888780",
            "width": 34,
            "height": 34,
            "border-width": 1.5,
            "border-color": "#ffffff",
        },
    },
    {"selector": "[device_type = 'PLC/OT']", "style": {"background-color": "#E24B4A"}},
    {"selector": "[device_type = 'Server']", "style": {"background-color": "#378ADD"}},
    {"selector": "[device_type = 'Gateway']", "style": {"background-color": "#1D9E75", "width": 40, "height": 40}},
    {"selector": "[device_type = 'IoT/Sensor']", "style": {"background-color": "#EF9F27"}},
    {"selector": "[device_type = 'Workstation']", "style": {"background-color": "#7F77DD"}},
    {"selector": "[risk >= 50]", "style": {"background-color": "#E24B4A"}},
    {"selector": "[risk >= 25][risk < 50]", "style": {"background-color": "#EF9F27"}},
    {"selector": "node:selected", "style": {"border-color": "#000000", "border-width": 3}},
    {
        "selector": "edge",
        "style": {
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.8,
            "line-color": "#B4B2A9",
            "target-arrow-color": "#B4B2A9",
            "width": 1.5,
            "label": "data(protocol)",
            "font-size": "9px",
            "color": "#888780",
        },
    },
]

_section_title_style = {
    "fontSize": "11px",
    "fontWeight": "600",
    "color": "#888780",
    "marginBottom": "8px",
    "textTransform": "uppercase",
    "letterSpacing": "0.05em",
}


def _metric_card(card_id: str, label: str) -> html.Div:
    return html.Div(
        [
            html.Div(
                label,
                style={
                    "fontSize": "10px",
                    "color": "#888780",
                    "textTransform": "uppercase",
                    "letterSpacing": "0.05em",
                    "marginBottom": "4px",
                },
            ),
            html.Div("–", id=card_id, style={"fontSize": "20px", "fontWeight": "600", "color": "#1A1A1A"}),
        ],
        style={
            "flex": "1",
            "padding": "12px 16px",
            "backgroundColor": "#FFFFFF",
            "borderRadius": "8px",
            "boxShadow": "0 1px 3px rgba(0,0,0,0.05)",
            "border": "1px solid #E8E8E4",
        },
    )


def phase1_layout() -> html.Div:
    ifaces = list_interfaces()
    iface_options = [{"label": f"{idx + 1}. {i}", "value": str(idx + 1)} for idx, i in enumerate(ifaces)]
    if not iface_options:
        iface_options = [{"label": "1. Default Interface", "value": "1"}]

    return html.Div(
        [
            # ── Top Control Bar ──────────────────────────────────────────────────
            html.Div(
                [
                    # PCAP Upload
                    dcc.Upload(
                        id="pcap-upload",
                        children=html.Div(["📁 Drag & Drop or ", html.B("Upload PCAP")]),
                        style={
                            "borderWidth": "1px",
                            "borderStyle": "dashed",
                            "borderColor": "#378ADD",
                            "borderRadius": "6px",
                            "padding": "6px 14px",
                            "textAlign": "center",
                            "cursor": "pointer",
                            "fontSize": "12px",
                            "backgroundColor": "#F4F8FC",
                            "color": "#1D5494",
                        },
                        multiple=False,
                    ),
                    # LAN Scan Button
                    html.Button(
                        "🔍 Scan Network",
                        id="scan-btn",
                        n_clicks=0,
                        style={
                            "background": "#378ADD",
                            "color": "#fff",
                            "border": "none",
                            "padding": "7px 16px",
                            "borderRadius": "6px",
                            "cursor": "pointer",
                            "fontWeight": "500",
                            "fontSize": "12px",
                        },
                    ),
                    # Interface selector
                    dcc.Dropdown(
                        id="iface-dropdown",
                        options=iface_options,
                        value=iface_options[0]["value"],
                        clearable=False,
                        style={"width": "260px", "fontSize": "12px"},
                        placeholder="Select NIC…",
                    ),
                    # BPF Input
                    dcc.Input(
                        id="bpf-input",
                        placeholder="BPF filter (e.g. 'not arp')",
                        style={
                            "width": "200px",
                            "padding": "6px 10px",
                            "fontSize": "12px",
                            "border": "1px solid #CCC",
                            "borderRadius": "4px",
                        },
                    ),
                    # Start Live Capture Button
                    html.Button(
                        "▶ Start Live Monitor",
                        id="start-btn",
                        n_clicks=0,
                        style={
                            "background": "#1D9E75",
                            "color": "#fff",
                            "border": "none",
                            "padding": "7px 16px",
                            "borderRadius": "6px",
                            "cursor": "pointer",
                            "fontWeight": "500",
                            "fontSize": "12px",
                        },
                    ),
                    # Stop Button
                    html.Button(
                        "■ Stop",
                        id="stop-btn",
                        n_clicks=0,
                        style={
                            "background": "#E24B4A",
                            "color": "#fff",
                            "border": "none",
                            "padding": "7px 14px",
                            "borderRadius": "6px",
                            "cursor": "pointer",
                            "fontSize": "12px",
                        },
                    ),
                    html.Span(id="capture-status", style={"fontSize": "12px", "color": "#666", "marginLeft": "8px"}),
                    html.Span(id="scan-progress", style={"fontSize": "12px", "color": "#378ADD", "marginLeft": "auto"}),
                ],
                style={
                    "display": "flex",
                    "gap": "10px",
                    "alignItems": "center",
                    "padding": "12px 20px",
                    "backgroundColor": "#FAFAFA",
                    "borderBottom": "1px solid #E8E8E4",
                    "flexWrap": "wrap",
                },
            ),
            # ── Summary Metric Cards ─────────────────────────────────────────────
            html.Div(
                [
                    _metric_card("metric-packets", "Total Packets"),
                    _metric_card("metric-ips", "Connected Users / IPs"),
                    _metric_card("metric-protocols", "Protocols Seen"),
                    _metric_card("metric-top-talker", "Top Talker / Bytes"),
                ],
                style={"display": "flex", "gap": "16px", "padding": "16px 20px"},
            ),
            # ── Main Topology & Asset Panel ──────────────────────────────────────
            html.Div(
                [
                    # Left: Topology Graph
                    html.Div(
                        [
                            html.Div("Network Topology Graph", style=_section_title_style),
                            cyto.Cytoscape(
                                id="cytoscape-topology",
                                layout={"name": "cose", "animate": True, "animationDuration": 500},
                                style={"width": "100%", "height": "380px", "backgroundColor": "#FDFDFD"},
                                elements=[],
                                stylesheet=CYTO_STYLESHEET,
                            ),
                        ],
                        style={
                            "flex": "1.4",
                            "padding": "16px",
                            "backgroundColor": "#FFFFFF",
                            "borderRadius": "8px",
                            "border": "1px solid #E8E8E4",
                        },
                    ),
                    # Right: Asset Table & Selected Node Details & Protocol Breakdown
                    html.Div(
                        [
                            html.Div("Asset Inventory", style=_section_title_style),
                            dash_table.DataTable(
                                id="asset-table",
                                columns=[
                                    {"name": "IP", "id": "ip"},
                                    {"name": "MAC", "id": "mac"},
                                    {"name": "Type", "id": "type"},
                                    {"name": "Ports", "id": "ports"},
                                ],
                                data=[],
                                style_table={"overflowY": "auto", "maxHeight": "140px"},
                                style_cell={"fontSize": "11px", "padding": "4px 8px"},
                                style_header={"fontWeight": "600", "backgroundColor": "#F7F7F5"},
                            ),
                            html.Div("User Inspection Details", style={**_section_title_style, "marginTop": "14px"}),
                            html.Div(
                                id="user-detail-panel",
                                children="Select a user from table or graph to inspect.",
                                style={
                                    "fontSize": "11px",
                                    "color": "#555",
                                    "minHeight": "60px",
                                    "padding": "8px",
                                    "backgroundColor": "#FAFAFA",
                                    "borderRadius": "4px",
                                },
                            ),
                            html.Div("Protocol Breakdown", style={**_section_title_style, "marginTop": "14px"}),
                            dcc.Graph(
                                id="protocol-chart",
                                config={"displayModeBar": False},
                                style={"height": "140px"},
                            ),
                        ],
                        style={
                            "flex": "1",
                            "padding": "16px",
                            "backgroundColor": "#FFFFFF",
                            "borderRadius": "8px",
                            "border": "1px solid #E8E8E4",
                            "display": "flex",
                            "flexDirection": "column",
                        },
                    ),
                ],
                style={"display": "flex", "gap": "16px", "padding": "0 20px 16px 20px"},
            ),
            # ── Live User / Flow Table Panel ─────────────────────────────────────
            html.Div(
                [
                    html.Div("Live User Activity & Threat Risk", style=_section_title_style),
                    dash_table.DataTable(
                        id="user-table",
                        columns=[
                            {"name": "IP Address", "id": "ip"},
                            {"name": "MAC", "id": "mac"},
                            {"name": "Packets", "id": "packets"},
                            {"name": "Data Usage", "id": "bytes_hr"},
                            {"name": "Connections", "id": "connections"},
                            {"name": "Top Protocol", "id": "top_protocol"},
                            {"name": "Risk Score", "id": "risk_score"},
                            {"name": "Last Seen", "id": "last_seen"},
                        ],
                        data=[],
                        sort_action="native",
                        style_table={"overflowY": "auto", "maxHeight": "200px"},
                        style_cell={"fontSize": "11px", "padding": "6px 10px"},
                        style_header={"fontWeight": "600", "backgroundColor": "#F7F7F5"},
                        style_data_conditional=[
                            {"if": {"filter_query": "{risk_score} >= 50"}, "backgroundColor": "#FEF2F0", "color": "#A32D2D"},
                            {"if": {"filter_query": "{risk_score} >= 25 && {risk_score} < 50"}, "backgroundColor": "#FDFAEE"},
                        ],
                        row_selectable="single",
                        selected_rows=[],
                    ),
                    html.Div("Parsed Packet Flows (PCAP / Live)", style={**_section_title_style, "marginTop": "16px"}),
                    dash_table.DataTable(
                        id="flow-table",
                        columns=[
                            {"name": "Src IP", "id": "src_ip"},
                            {"name": "Dst IP", "id": "dst_ip"},
                            {"name": "Protocol", "id": "protocol"},
                            {"name": "Packets", "id": "packets"},
                            {"name": "Bytes", "id": "bytes"},
                            {"name": "Duration (s)", "id": "duration_s"},
                        ],
                        data=[],
                        sort_action="native",
                        style_table={"overflowY": "auto", "maxHeight": "200px"},
                        style_cell={"fontSize": "11px", "padding": "6px 10px"},
                        style_header={"fontWeight": "600", "backgroundColor": "#F7F7F5"},
                    ),
                ],
                style={
                    "padding": "16px",
                    "margin": "0 20px 20px 20px",
                    "backgroundColor": "#FFFFFF",
                    "borderRadius": "8px",
                    "border": "1px solid #E8E8E4",
                },
            ),
            # Polling interval
            dcc.Interval(id="live-interval", interval=1500, disabled=False),
        ],
        style={"fontFamily": "Segoe UI, -apple-system, Roboto, sans-serif", "backgroundColor": "#F7F7F5", "minHeight": "100vh"},
    )


# ── Callbacks ─────────────────────────────────────────────────────────────────

@callback(
    Output("live-interval", "disabled"),
    Output("capture-status", "children"),
    Input("start-btn", "n_clicks"),
    Input("stop-btn", "n_clicks"),
    State("iface-dropdown", "value"),
    State("bpf-input", "value"),
    prevent_initial_call=True,
)
def toggle_capture(start_clicks, stop_clicks, iface, bpf):
    triggered = ctx.triggered_id
    if triggered == "start-btn":
        ok = start_capture(interface=iface or "1", bpf_filter=bpf or "")
        if ok:
            return False, "● Capturing live network packets…"
        return True, "⚠ Failed to start capture (Check tshark installation)"
    elif triggered == "stop-btn":
        stop_capture()
        return True, "■ Capture stopped"
    return True, ""


@callback(
    Output("scan-btn", "disabled"),
    Input("scan-btn", "n_clicks"),
    prevent_initial_call=True,
)
def trigger_network_scan(n):
    if n:
        start_network_scan()
        return True
    return False


@callback(
    Output("cytoscape-topology", "elements"),
    Output("user-table", "data"),
    Output("asset-table", "data"),
    Output("metric-packets", "children"),
    Output("metric-ips", "children"),
    Output("metric-protocols", "children"),
    Output("metric-top-talker", "children"),
    Output("protocol-chart", "figure"),
    Output("scan-progress", "children"),
    Output("scan-btn", "disabled", allow_duplicate=True),
    Input("live-interval", "n_intervals"),
    Input("pcap-upload", "contents"),
    State("pcap-upload", "filename"),
    prevent_initial_call=True,
)
def refresh_dashboard_data(n_intervals, pcap_contents, pcap_filename):
    triggered = ctx.triggered_id

    # Handle PCAP Upload trigger
    if triggered == "pcap-upload" and pcap_contents:
        parsed = parse_pcap_contents(pcap_contents, pcap_filename or "upload.pcap")
        return (
            parsed["elements"],
            [],  # user table remains for live monitor
            parsed["assets"],
            parsed["total_packets"],
            parsed["unique_ips"],
            parsed["protocols_count"],
            parsed["top_talker"],
            parsed["proto_figure"],
            "PCAP Loaded",
            False,
        )

    # Handle Live tshark snapshot & Network Scan polling
    snap = get_snapshot()
    users = snap.get("users", {})
    scan_state = get_scan_state()

    # User table rows
    rows = []
    for u in sorted(users.values(), key=lambda x: x["bytes"], reverse=True):
        rows.append({
            "ip": u["ip"],
            "mac": u["mac"] or "–",
            "packets": f"{u['packets']:,}",
            "bytes_hr": format_bytes(u["bytes"]),
            "connections": u["connections"],
            "top_protocol": u["top_protocol"],
            "risk_score": u["risk_score"],
            "last_seen": u["last_seen"] or "–",
        })

    # Assets table
    assets = []
    scan_hosts = scan_state.get("hosts") or []
    for h in scan_hosts:
        ports_str = ", ".join(str(p.get("port")) for p in (h.get("ports") or [])[:5]) or "None"
        assets.append({
            "ip": h.get("ip", ""),
            "mac": h.get("mac", "—"),
            "type": h.get("device_type", "Unknown"),
            "ports": ports_str,
        })

    # Build Cytoscape Topology Elements
    elements = []
    node_ids = set()

    # Add LAN scan elements
    if scan_hosts:
        gw_ip = scan_state.get("gateway_ip")
        for h in scan_hosts:
            ip = h.get("ip")
            if not ip:
                continue
            dtype = h.get("device_type") or classify_device(h)
            elements.append({
                "data": {
                    "id": ip,
                    "label": f"{ip}\n{dtype}",
                    "device_type": dtype,
                    "mac": h.get("mac") or "",
                    "ports": [p.get("port") for p in (h.get("ports") or []) if p.get("port")],
                }
            })
            node_ids.add(ip)
            if gw_ip and ip != gw_ip:
                elements.append({"data": {"id": f"{ip}-{gw_ip}", "source": ip, "target": gw_ip, "protocol": "ARP"}})

    # Add Live tshark capture elements if no scan hosts or in addition
    for ip, u in users.items():
        if ip not in node_ids:
            elements.append({
                "data": {
                    "id": ip,
                    "label": f"{ip}\n{u['top_protocol']}",
                    "device_type": "Workstation",
                    "risk": u["risk_score"],
                }
            })
            node_ids.add(ip)

    # Metrics calculation
    total_pkts = f"{snap.get('packets_total', 0):,}"
    total_users = str(len(users) or len(scan_hosts))
    
    all_protos: dict[str, int] = {}
    for u in users.values():
        for p, cnt in u.get("protocols", {}).items():
            all_protos[p] = all_protos.get(p, 0) + cnt

    top_proto_str = max(all_protos, key=all_protos.get) if all_protos else "–"
    top_talker_str = format_bytes(snap.get("bytes_total", 0))

    # Protocol Figure
    if all_protos:
        sorted_p = sorted(all_protos.items(), key=lambda x: x[1], reverse=True)[:8]
        labels, values = zip(*sorted_p)
        fig = go.Figure(go.Bar(x=list(values), y=list(labels), orientation="h", marker_color="#378ADD"))
        fig.update_layout(
            margin=dict(l=0, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(size=11),
            height=140,
        )
    else:
        fig = go.Figure()

    scan_msg = ""
    if scan_state.get("status") == "scanning":
        scan_msg = f"Scanning LAN: {scan_state.get('progress', 0)}%"
    elif scan_state.get("status") == "done":
        scan_msg = f"Scan complete ({len(scan_hosts)} hosts)"

    scan_btn_disabled = scan_state.get("status") == "scanning"

    return (
        elements,
        rows,
        assets,
        total_pkts,
        total_users,
        str(len(all_protos)) if all_protos else top_proto_str,
        top_talker_str,
        fig,
        scan_msg,
        scan_btn_disabled,
    )


@callback(
    Output("user-detail-panel", "children"),
    Input("user-table", "selected_rows"),
    State("user-table", "data"),
    prevent_initial_call=True,
)
def show_user_detail(selected, data):
    if not selected or not data:
        return "Select a user from table to inspect details."
    row = data[selected[0]]
    snap = get_snapshot()
    u = snap.get("users", {}).get(row["ip"], {})
    protos = u.get("protocols", {})
    proto_str = ", ".join(f"{p}({c})" for p, c in protos.items()) if protos else "None"

    return html.Div(
        [
            html.Div([html.B("IP: "), row["ip"]]),
            html.Div([html.B("MAC: "), row.get("mac", "–")]),
            html.Div([html.B("Packets: "), str(row.get("packets", 0))]),
            html.Div([html.B("Data Usage: "), row.get("bytes_hr", "0 B")]),
            html.Div([html.B("Connections: "), str(row.get("connections", 0))]),
            html.Div(
                [
                    html.B("Risk Score: "),
                    html.Span(
                        f"{row.get('risk_score', 0)}",
                        style={
                            "color": "#E24B4A"
                            if row.get("risk_score", 0) >= 50
                            else "#EF9F27"
                            if row.get("risk_score", 0) >= 25
                            else "#1D9E75",
                            "fontWeight": "bold",
                        },
                    ),
                ]
            ),
            html.Div([html.B("First Seen: "), u.get("first_seen", "–")]),
            html.Div([html.B("Last Seen: "), u.get("last_seen", "–")]),
            html.Div([html.B("Protocols: "), proto_str]),
        ],
        style={"lineHeight": "1.6", "fontSize": "11px"},
    )
