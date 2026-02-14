from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_pdf_report(payload: dict) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title="SecureScan Pro v5 Industry Report")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="BodySmall", parent=styles["Normal"], fontSize=9, leading=12))

    story = [Paragraph("SecureScan Pro v5 — OWASP Top 5 Assessment Report", styles["Title"]), Spacer(1, 10)]

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(payload.get("executive_summary", "No summary generated."), styles["BodySmall"]))
    story.append(Paragraph(f"Target: {payload.get('url', 'unknown')} | Timestamp: {payload.get('timestamp', datetime.now(timezone.utc).isoformat())}", styles["BodySmall"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Risk Equation Section", styles["Heading2"]))
    story.append(Paragraph("Risk = Exposure × Exploitability × (1 − Mitigation), weighted by confidence.", styles["BodySmall"]))
    story.append(Paragraph(f"Average confidence: {payload.get('confidence_average', 0)}%", styles["BodySmall"]))
    story.append(Paragraph(f"CVSS Composite: {payload.get('cvss_score', 0)} ({payload.get('cvss_severity', 'Low')})", styles["BodySmall"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Evidence Correlation Explanation", styles["Heading2"]))
    story.append(Paragraph("Each control domain uses five validation stages: baseline capture, non-destructive probe, error normalization, behavioral delta comparison, and correlated evidence scoring. This defensive model avoids exploitation payloads.", styles["BodySmall"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Technical Appendix", styles["Heading2"]))
    rows = [["Control Domain", "Severity", "Weighted Risk", "Confidence", "Evidence Highlights"]]
    for item in payload.get("owasp_findings", []):
        evidence = "; ".join(f"{ev['name']}:s={ev['score']}/r={ev['reliability']}/w={ev['weight']}" for ev in item.get("evidence", []))
        rows.append([
            item.get("domain", "Unknown"),
            item.get("severity", "Informational"),
            str(item.get("risk_output", {}).get("weighted_risk", 0.0)),
            f"{item.get('confidence', 0)}%",
            evidence[:150],
        ])

    table = Table(rows, colWidths=[105, 70, 65, 60, 225])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#192a56")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#7f8fa6")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.extend([table, Spacer(1, 10)])

    story.append(Paragraph("Limitations", styles["Heading2"]))
    for limitation in payload.get("limitations", [
        "Passive behavioral analysis may not detect deep workflow logic flaws.",
        "Authentication-dependent findings can be underrepresented without authorized test identities.",
        "Network middleware can influence confidence and observable signals.",
    ]):
        story.append(Paragraph(f"• {limitation}", styles["BodySmall"]))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
