from __future__ import annotations

CONFIDENCE_MULTIPLIER = {
    "Informational": 0.0,
    "Low": 0.6,
    "Medium": 0.85,
    "High": 1.0,
}

BASE_SCORE_MAP = {
    "SQL Injection (Passive)": 9.8,
    "Reflected XSS (Passive Reflection)": 6.1,
    "CSRF Protections": 5.4,
    "Security Headers": 4.2,
    "TLS/SSL Certificate": 7.4,
}


def _severity_label(score: float) -> str:
    if score == 0:
        return "Low"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def score_findings(findings: list[dict]) -> dict:
    weighted_scores: list[float] = []
    csp_present = any(f.get("name") == "Security Headers" and f.get("csp_present") for f in findings)

    for finding in findings:
        if not finding.get("vulnerable"):
            continue
        name = finding.get("name", "")
        base = BASE_SCORE_MAP.get(name, 3.5)
        confidence = finding.get("confidence", "Medium")
        multiplier = CONFIDENCE_MULTIPLIER.get(confidence, 0.8)

        if name == "Reflected XSS (Passive Reflection)" and csp_present:
            multiplier *= 0.7  # CSP-aware severity reduction

        weighted_scores.append(base * multiplier)

    if not weighted_scores:
        score = 0.0
    else:
        aggregate = sum(weighted_scores) / len(weighted_scores)
        score = round(min(10.0, aggregate + max(0.0, len(weighted_scores) - 1) * 0.35), 1)

    return {
        "score": score,
        "severity": _severity_label(score),
        "method": "CVSS v3.1-inspired weighted aggregation with confidence multipliers",
    }
