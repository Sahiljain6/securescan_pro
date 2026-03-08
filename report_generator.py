from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_pdf_report(payload: dict) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title="SecureScan Pro Security Report")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="BodySmall", parent=styles["Normal"], fontSize=9, leading=12))

    story = [Paragraph("SecureScan Pro — Professional Vulnerability Assessment", styles["Title"]), Spacer(1, 10)]
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(payload.get("executive_summary", "No summary generated."), styles["BodySmall"]))
    story.append(
        Paragraph(
            f"Target: {payload.get('url', 'unknown')} | Timestamp: {payload.get('timestamp', datetime.now(timezone.utc).isoformat())}",
            styles["BodySmall"],
        )
    )
    story.append(Spacer(1, 8))

    story.append(Paragraph("Risk Model", styles["Heading2"]))
    story.append(Paragraph("Risk Score = (Exposure × Exploitability × Impact) × Confidence", styles["BodySmall"]))
    story.append(Paragraph(f"CVSS-style composite: {payload.get('cvss_score', 0)} ({payload.get('cvss_severity', 'Low')})", styles["BodySmall"]))
    story.append(Paragraph(f"Dashboard risk score: {payload.get('dashboard_data', {}).get('risk_score', 0)} / 10", styles["BodySmall"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("AI-Generated Analysis", styles["Heading2"]))
    ai = payload.get("ai_analysis", {})
    story.append(Paragraph(f"Engine: {ai.get('engine', 'fallback')} | Model: {ai.get('model', 'N/A')}", styles["BodySmall"]))
    story.append(Paragraph(ai.get("summary", "No AI summary available."), styles["BodySmall"]))
    if ai.get("reason"):
        story.append(Paragraph(f"Fallback reason: {ai.get('reason')}", styles["BodySmall"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Vulnerability Findings", styles["Heading2"]))
    rows = [["Vulnerability", "Severity", "CVSS", "OWASP", "Mitigation"]]
    for finding in payload.get("hybrid_findings", []):
        rows.append(
            [
                str(finding.get("vulnerability", "Unknown"))[:55],
                str(finding.get("severity") or finding.get("ml", {}).get("severity", "Low")),
                str(finding.get("risk", {}).get("cvss_score", 0)),
                str(finding.get("owasp_category", "Uncategorized"))[:40],
                str(finding.get("mitigation", "Apply defensive hardening controls."))[:85],
            ]
        )

    if len(rows) == 1:
        rows.append(["No vulnerabilities detected", "Informational", "0", "N/A", "Maintain monitoring and patch cadence."])

    table = Table(rows, colWidths=[120, 55, 45, 110, 180])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#192a56")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#7f8fa6")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.extend([table, Spacer(1, 10)])

    story.append(Paragraph("Mitigation Recommendations", styles["Heading2"]))
    for recommendation in payload.get("recommendations", ["Implement secure coding controls and continuous monitoring."]):
        story.append(Paragraph(f"• {recommendation}", styles["BodySmall"]))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
