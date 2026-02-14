from __future__ import annotations

SEVERITY_WEIGHTS = {
    "Informational": 0.2,
    "Low": 0.45,
    "Medium": 0.7,
    "High": 0.9,
    "Critical": 1.0,
}


def _severity_label(score: float) -> str:
    if score < 1.5:
        return "Low"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def score_findings(findings: list[dict]) -> dict:
    if not findings:
        return {
            "score": 0.0,
            "severity": "Low",
            "method": "CVSS-inspired exploitability/mitigation weighting",
        }

    weighted: list[float] = []
    for finding in findings:
        exploitability = float(finding.get("exploitability_score", 0.0))
        confidence = float(finding.get("confidence", 0.0)) / 100.0
        mitigation_weight = 0.75 if finding.get("mitigation_present") else 1.0
        severity_weight = SEVERITY_WEIGHTS.get(finding.get("severity", "Low"), 0.5)
        weighted.append(exploitability * confidence * mitigation_weight * severity_weight)

    aggregate = sum(weighted) / len(weighted)
    score = round(min(10.0, aggregate + (len([w for w in weighted if w > 0]) - 1) * 0.3), 1)
    return {
        "score": score,
        "severity": _severity_label(score),
        "method": "CVSS-inspired exploitability score × confidence × mitigation weighting",
    }
