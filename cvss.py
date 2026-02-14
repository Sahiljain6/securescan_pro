from __future__ import annotations

FINDING_SCORES = {
    "SQL Injection (Passive)": 9.1,
    "Reflected XSS (Passive Reflection)": 6.1,
    "CSRF Protections": 5.3,
    "Security Headers": 4.0,
    "TLS/SSL Certificate": 7.5,
}


def score_findings(findings: list[dict]) -> dict:
    active_scores = []
    for finding in findings:
        if finding.get("vulnerable"):
            active_scores.append(FINDING_SCORES.get(finding.get("name"), 3.0))

    if not active_scores:
        score = 0.0
    else:
        score = min(10.0, round(sum(active_scores) / len(active_scores) + (0.35 * (len(active_scores) - 1)), 1))

    if score == 0:
        severity = "Low"
    elif score < 4.0:
        severity = "Low"
    elif score < 7.0:
        severity = "Medium"
    elif score < 9.0:
        severity = "High"
    else:
        severity = "Critical"

    return {"score": score, "severity": severity}
