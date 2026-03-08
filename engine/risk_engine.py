from __future__ import annotations

from math import isfinite


def calculate_risk_score(header_score: float, open_ports: int, redirect_count: int, tls_issues: int) -> float:
    """
    Raw formula from requirements:
        (10 - header_score) * open_ports * redirect_count * tls_issues
    Normalized to CVSS-style 0..10.
    """
    raw_score = max(0.0, (10.0 - float(header_score)))
    raw_score *= max(0, int(open_ports))
    raw_score *= max(0, int(redirect_count))
    raw_score *= max(0, int(tls_issues))

    if raw_score <= 0:
        return 0.0

    normalized = (raw_score / (raw_score + 40.0)) * 10.0
    if not isfinite(normalized):
        return 0.0
    return round(max(0.0, min(10.0, normalized)), 2)


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"
