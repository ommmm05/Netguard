"""
Export utilities: CSV and PDF (Phase 3).

``export_alerts_csv``  — quick tabular export of alert rows.
``build_simple_pdf``   — bare-bones text PDF (legacy).
``build_forensic_pdf`` — professional forensic report with tables,
                         severity coloring, SHAP features, timeline,
                         and remediation steps.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any, Iterable

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


# ─── CSV export (unchanged) ─────────────────────────────────────────
def export_alerts_csv(alerts: Iterable[dict[str, Any]]) -> bytes:
    buf = io.StringIO()
    rows = list(alerts)
    fields = list({k for r in rows for k in r.keys()})
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({k: ("" if v is None else v) for k, v in r.items()})
    return buf.getvalue().encode("utf-8")


# ─── Legacy simple PDF (kept for backward compat) ───────────────────
def build_simple_pdf(title: str, lines: list[str]) -> bytes:
    bio = io.BytesIO()
    c = canvas.Canvas(bio, pagesize=letter)
    c.setTitle(title)
    w, h = letter
    y = h - 72
    c.setFont("Helvetica-Bold", 14)
    c.drawString(72, y, title)
    y -= 24
    c.setFont("Helvetica", 10)
    for line in lines:
        for chunk in [line[i : i + 95] for i in range(0, len(line), 95)] or [""]:
            c.drawString(72, y, chunk)
            y -= 12
            if y < 72:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = h - 72
    c.showPage()
    c.save()
    return bio.getvalue()


# ─── Severity color map ─────────────────────────────────────────────
_SEV_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#64748b"),
}


def _sev_color(sev: str) -> colors.Color:
    return _SEV_COLORS.get((sev or "").lower(), colors.grey)


# ─── Professional forensic PDF ──────────────────────────────────────
def build_forensic_pdf(
    alert: dict[str, Any],
    shap_top: list[dict[str, Any]] | None = None,
    timeline: list[dict[str, Any]] | None = None,
    remediation: list[str] | None = None,
    narrative: str = "",
    report_id: str = "",
) -> bytes:
    """
    Generate a professional forensic incident report PDF.

    Sections:
      1. Header with report ID and timestamp
      2. Alert details table
      3. SHAP top features table
      4. Incident timeline
      5. Narrative / LLM summary
      6. Remediation steps
      7. Footer
    """
    bio = io.BytesIO()
    doc = SimpleDocTemplate(
        bio,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    story: list[Any] = []

    # Custom styles
    title_style = ParagraphStyle("NGTitle", parent=styles["Title"], fontSize=18, textColor=colors.HexColor("#0e7490"))
    h2_style = ParagraphStyle("NGH2", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#1e293b"))
    body_style = ParagraphStyle("NGBody", parent=styles["Normal"], fontSize=10, leading=14)
    small_style = ParagraphStyle("NGSmall", parent=styles["Normal"], fontSize=8, textColor=colors.grey)

    # ── 1. Header ──
    story.append(Paragraph("NetGuard — Forensic Incident Report", title_style))
    ts_now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"Report ID: <b>{report_id or 'N/A'}</b> &nbsp;|&nbsp; Generated: {ts_now}", small_style))
    story.append(Spacer(1, 16))

    # ── 2. Alert details table ──
    sev = str(alert.get("severity", "info"))
    story.append(Paragraph("Alert Details", h2_style))
    detail_data = [
        ["Field", "Value"],
        ["Alert ID", str(alert.get("id", "—"))],
        ["Title", str(alert.get("title", "—"))],
        ["Severity", sev.upper()],
        ["Attack Type", str(alert.get("attackType") or alert.get("attack_type") or "—")],
        ["Confidence", f"{alert.get('confidence', 0):.1f}%"],
        ["Source IP", str(alert.get("srcIp") or alert.get("src_ip") or "—")],
        ["Destination IP", str(alert.get("dstIp") or alert.get("dst_ip") or "—")],
        ["Model", str(alert.get("model", "RF + XGBoost + IsolationForest"))],
    ]
    t = Table(detail_data, colWidths=[1.8 * inch, 4.5 * inch])
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0e7490")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(t)
    story.append(Spacer(1, 16))

    # ── 3. SHAP features table ──
    if shap_top:
        story.append(Paragraph("SHAP Feature Contributions (Random Forest)", h2_style))
        shap_data = [["Rank", "Feature", "Value", "SHAP Impact"]]
        for i, row in enumerate(shap_top[:10], 1):
            shap_data.append([
                str(i),
                str(row.get("feature", "")),
                f"{row.get('value', 0):.4f}",
                f"{row.get('shap', 0):.4f}",
            ])
        st = Table(shap_data, colWidths=[0.5 * inch, 2.5 * inch, 1.5 * inch, 1.5 * inch])
        st.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ALIGN", (0, 0), (0, -1), "CENTER"),
                ("ALIGN", (2, 0), (-1, -1), "RIGHT"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(st)
        story.append(Spacer(1, 16))

    # ── 4. Timeline ──
    if timeline:
        story.append(Paragraph("Incident Timeline", h2_style))
        tl_data = [["Time", "Event", "Severity", "Hosts"]]
        for ev in timeline[:20]:
            tl_data.append([
                str(ev.get("time") or ev.get("timestamp", "—"))[:19],
                str(ev.get("event") or ev.get("title", "—"))[:50],
                str(ev.get("severity", "info")),
                str(ev.get("host", ""))[:30],
            ])
        tt = Table(tl_data, colWidths=[1.2 * inch, 2.5 * inch, 0.9 * inch, 1.7 * inch])
        tt.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f9fafb")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        story.append(tt)
        story.append(Spacer(1, 16))

    # ── 5. Narrative ──
    if narrative:
        story.append(Paragraph("Incident Narrative", h2_style))
        # Split long narrative into paragraphs
        for para in narrative.split("\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), body_style))
                story.append(Spacer(1, 6))
        story.append(Spacer(1, 10))

    # ── 6. Remediation ──
    if remediation:
        story.append(Paragraph("Recommended Actions", h2_style))
        for i, step in enumerate(remediation, 1):
            story.append(Paragraph(f"<b>{i}.</b> {step}", body_style))
            story.append(Spacer(1, 4))
        story.append(Spacer(1, 10))

    # ── 7. Footer ──
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "This report was generated by NetGuard — AI-Driven Network Visibility, Threat Detection &amp; Forensics Platform. "
        "Classification: CONFIDENTIAL. For authorized personnel only.",
        small_style,
    ))

    doc.build(story)
    return bio.getvalue()
