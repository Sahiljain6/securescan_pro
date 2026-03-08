from __future__ import annotations


def clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))


def calculate_risk(
    exposure: float,
    exploitability: float,
    impact: float,
    confidence: float,
) -> dict[str, float | str]:
    """Risk Score = (Exposure × Exploitability × Impact) × Confidence."""
    exposure = clamp(exposure)
    exploitability = clamp(exploitability)
    impact = clamp(impact)
    confidence = clamp(confidence)

    normalized_risk = clamp((exposure * exploitability * impact) * confidence)
    score = round(normalized_risk * 10, 2)

    if score >= 9:
        severity = "Critical"
    elif score >= 7:
        severity = "High"
    elif score >= 4:
        severity = "Medium"
    elif score > 0:
        severity = "Low"
    else:
        severity = "Informational"

    return {
        "risk": round(normalized_risk, 4),
        "cvss_score": score,
        "severity": severity,
        "confidence": round(confidence, 3),
        "equation": "Risk Score = (Exposure × Exploitability × Impact) × Confidence",
    }
