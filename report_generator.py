from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_pdf_report(payload: dict) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title="SecureScan Pro v4 Academic Report")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="BodySmall", parent=styles["Normal"], fontSize=9, leading=12))

    story = [Paragraph("SecureScan Pro v4 — OWASP Top 5 Structured Assessment", styles["Title"]), Spacer(1, 10)]
    story.append(Paragraph("Abstract", styles["Heading2"]))
    story.append(Paragraph("This academic-grade report presents a defensive and passive web security assessment. No exploit tooling or aggressive payload execution is performed.", styles["BodySmall"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Methodology", styles["Heading2"]))
    story.append(Paragraph("Multi-stage validation was applied across five OWASP domains with evidence collection, mitigation-aware scoring, and false-positive suppression.", styles["BodySmall"]))
    story.append(Paragraph(f"Timestamp: {payload.get('timestamp', datetime.now(timezone.utc).isoformat())}", styles["BodySmall"]))
    story.append(Paragraph(f"Target URL: {payload['url']}", styles["BodySmall"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Risk Modeling Explanation", styles["Heading2"]))
    story.append(Paragraph("Risk = Exposure × Exploitability × (1 − Mitigation Strength)", styles["BodySmall"]))
    story.append(Paragraph(f"Average confidence: {payload.get('confidence_average', 0)}%", styles["BodySmall"]))
    story.append(Paragraph(f"CVSS: {payload['cvss_score']} ({payload['cvss_severity']})", styles["BodySmall"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Domain-by-Domain Analysis", styles["Heading2"]))
    rows = [["Domain", "Severity", "Risk", "Confidence", "Evidence Summary"]]
    for item in payload.get("owasp_findings", []):
        evidence_summary = "; ".join(f"{e['name']}:s={e['score']}/r={e['reliability']}/w={e['weight']}" for e in item.get("evidence", []))
        rows.append([
            item.get("domain", "Unknown"),
            item.get("severity", "Informational"),
            str(item.get("risk_output", {}).get("risk", 0.0)),
            f"{item.get('confidence', 0)}%",
            evidence_summary[:140],
        ])

    table = Table(rows, colWidths=[100, 62, 52, 62, 240])
    table.setStyle(
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
    story.extend([table, Spacer(1, 10)])

    story.append(Paragraph("Limitations", styles["Heading2"]))
    story.append(Paragraph("• Passive observations may underrepresent logic-level vulnerabilities that require authenticated business-flow testing.", styles["BodySmall"]))
    story.append(Paragraph("• Environmental controls (WAF/CDN/rate limiting) can suppress observable evidence and confidence.", styles["BodySmall"]))
    story.append(Paragraph("• Results should be validated with approved secure code review and controlled internal testing.", styles["BodySmall"]))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
