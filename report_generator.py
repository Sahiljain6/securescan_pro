from __future__ import annotations

from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_pdf_report(payload: dict) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title="SecureScan Pro v2 Report")
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("SecureScan Pro v2 - Vulnerability Assessment Report", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", styles["Normal"]))
    story.append(Paragraph(f"Target URL: {payload['url']}", styles["Normal"]))
    story.append(Paragraph(f"Phishing Verdict: {payload['phishing_result']} ({payload['phishing_probability']}%)", styles["Normal"]))
    story.append(Spacer(1, 14))

    story.append(Paragraph("OWASP Findings", styles["Heading2"]))
    finding_rows = [["Control", "Status", "Details"]]
    for item in payload["owasp_findings"]:
        status = "Issue Detected" if item["vulnerable"] else "No Issue"
        finding_rows.append([item["name"], status, item["details"]])
    findings_table = Table(finding_rows, colWidths=[165, 95, 250])
    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#162447")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#9aa5ce")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )
    story.append(findings_table)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Risk Summary", styles["Heading2"]))
    story.append(Paragraph(f"CVSS Score: {payload['cvss_score']} ({payload['cvss_severity']})", styles["Normal"]))
    open_ports = ", ".join(str(p) for p in payload["open_ports"]) if payload["open_ports"] else "None detected"
    story.append(Paragraph(f"Open Ports: {open_ports}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Recommendations", styles["Heading2"]))
    for rec in payload["recommendations"]:
        story.append(Paragraph(f"• {rec}", styles["Normal"]))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
