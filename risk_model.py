from __future__ import annotations

from typing import Any


def clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))


def weighted_evidence_strength(evidence_items: list[dict[str, Any]]) -> float:
    """Aggregate normalized evidence strength using per-item reliability and weight."""
    if not evidence_items:
        return 0.0

    weighted_sum = 0.0
    total_weight = 0.0
    for evidence in evidence_items:
        score = clamp(float(evidence.get("score", 0.0)))
        reliability = clamp(float(evidence.get("reliability", 0.7)))
        weight = max(0.0, float(evidence.get("weight", 1.0)))
        weighted_sum += score * reliability * weight
        total_weight += weight

    return 0.0 if total_weight == 0 else clamp(weighted_sum / total_weight)


def confidence_score(evidence_strength: float, stage_coverage: float, mitigation_strength: float) -> float:
    """Confidence is improved by evidence + coverage and reduced by strong mitigations."""
    value = (0.55 * clamp(evidence_strength)) + (0.35 * clamp(stage_coverage)) + (0.10 * (1 - clamp(mitigation_strength)))
    return round(clamp(value) * 100, 1)


def false_positive_suppression(
    evidence_strength: float,
    contradictory_signals: int,
    mitigation_strength: float,
) -> float:
    """Lower suppression factor means higher FP suppression."""
    contradiction_penalty = min(0.45, contradictory_signals * 0.1)
    mitigation_penalty = 0.35 * clamp(mitigation_strength)
    suppression = 1.0 - contradiction_penalty - mitigation_penalty
    return clamp(suppression, minimum=0.25, maximum=1.0)


def calculate_risk(
    exposure: float,
    exploitability: float,
    mitigation_strength: float,
    evidence_strength: float,
    contradictory_signals: int,
    stage_coverage: float,
) -> dict[str, float | str]:
    """
    Risk equation:
        Risk = Exposure × Exploitability × (1 − Mitigation Strength)
    With defensive modifiers for evidence weighting and false-positive suppression.
    """
    base_exposure = clamp(exposure)
    base_exploitability = clamp(exploitability)
    mitigation = clamp(mitigation_strength)
    evidence = clamp(evidence_strength)

    base_risk = base_exposure * base_exploitability * (1 - mitigation)
    fp_factor = false_positive_suppression(evidence, contradictory_signals, mitigation)
    final_risk = clamp(base_risk * ((0.6 + 0.4 * evidence) * fp_factor))

    confidence = confidence_score(evidence, stage_coverage, mitigation)

    if final_risk >= 0.7:
        severity = "Critical"
    elif final_risk >= 0.5:
        severity = "High"
    elif final_risk >= 0.25:
        severity = "Medium"
    elif final_risk >= 0.1:
        severity = "Low"
    else:
        severity = "Informational"

    return {
        "risk": round(final_risk, 4),
        "base_risk": round(base_risk, 4),
        "confidence": confidence,
        "false_positive_factor": round(fp_factor, 3),
        "severity": severity,
    }
