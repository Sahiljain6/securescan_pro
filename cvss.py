from __future__ import annotations

SEVERITY_WEIGHTS = {
    "Informational": 0.2,
    "Low": 0.45,
    "Medium": 0.7,
    "High": 0.9,
    "Critical": 1.0,
}


def _severity_label(score: float) -> str:
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
            "method": "Risk-model-inspired confidence and mitigation weighting",
        }

    weighted: list[float] = []
    for finding in findings:
        risk = float(finding.get("risk_output", {}).get("risk", 0.0)) * 10
        confidence = float(finding.get("confidence", 0.0)) / 100.0
        mitigation_strength = float(finding.get("risk_inputs", {}).get("mitigation_strength", 0.0))
        mitigation_weight = max(0.35, 1 - mitigation_strength)
        severity_weight = SEVERITY_WEIGHTS.get(finding.get("severity", "Low"), 0.5)
        weighted.append(risk * confidence * mitigation_weight * severity_weight)

    aggregate = sum(weighted) / len(weighted)
    score = round(min(10.0, aggregate + (len([w for w in weighted if w > 0.35]) - 1) * 0.2), 1)
    return {
        "score": score,
        "severity": _severity_label(score),
        "method": "Risk (Exposure × Exploitability × (1−Mitigation)) with confidence/evidence weighting",
    }
