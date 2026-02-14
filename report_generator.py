from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_pdf_report(payload: dict) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title="SecureScan Pro v2 Report")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="BodySmall", parent=styles["Normal"], fontSize=9, leading=12))

    story = [Paragraph("SecureScan Pro v2 — Enterprise Web Security Assessment", styles["Title"]), Spacer(1, 10)]
    story.append(Paragraph(f"Timestamp: {payload.get('timestamp', datetime.now(timezone.utc).isoformat())}", styles["Normal"]))
    story.append(Paragraph(f"Target URL: {payload['url']}", styles["Normal"]))
    story.append(Paragraph(f"Phishing Verdict: {payload['phishing_result']} ({payload['phishing_probability']}%)", styles["Normal"]))
    story.append(Paragraph(f"CVSS v3.1: {payload['cvss_score']} ({payload['cvss_severity']})", styles["Normal"]))
    story.append(Spacer(1, 14))

    story.append(Paragraph("OWASP Structured Findings", styles["Heading2"]))
    finding_rows = [["Vulnerability", "Status", "Exploitability", "Confidence", "Severity", "Mitigation", "Explanation"]]
    for item in payload["owasp_findings"]:
        finding_rows.append(
            [
                item["vulnerability"],
                "Informational" if item["exploitability_score"] < 1.5 else "Issue Detected",
                str(item["exploitability_score"]),
                f"{item.get('confidence', 0)}%",
                item["severity"],
                "Yes" if item.get("mitigation_present") else "No",
                item["explanation"],
            ]
        )
    findings_table = Table(finding_rows, colWidths=[95, 70, 65, 60, 52, 50, 125])
    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#162447")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#9aa5ce")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.extend([findings_table, Spacer(1, 12)])

    story.append(Paragraph("Multi-Stage Analysis", styles["Heading2"]))
    for stage in payload.get("owasp_stages", []):
        stage_name = stage.get("stage", "Unnamed Stage")
        stage_details = ", ".join(f"{k}={v}" for k, v in stage.items() if k != "stage")
        story.append(Paragraph(f"<b>{stage_name}</b>", styles["BodySmall"]))
        story.append(Paragraph(stage_details, styles["BodySmall"]))
        story.append(Spacer(1, 4))

    open_ports = ", ".join(str(port) for port in payload.get("open_ports", [])) or "None detected"
    story.append(Paragraph("Network Exposure", styles["Heading2"]))
    story.append(Paragraph(f"Open common ports: {open_ports}", styles["Normal"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(payload.get("executive_summary", "No executive summary generated."), styles["BodySmall"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Recommendations", styles["Heading2"]))
    for recommendation in payload.get("recommendations", []):
        story.append(Paragraph(f"• {recommendation}", styles["BodySmall"]))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
