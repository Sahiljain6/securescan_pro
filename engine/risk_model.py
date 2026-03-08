from __future__ import annotations


def clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))


def scanner_consensus_factor(scanner_count: int) -> float:
    """Increase score confidence as more independent scanners agree."""
    if scanner_count <= 1:
        return 1.0
    return round(min(1.35, 1.0 + ((scanner_count - 1) * 0.12)), 2)


def calculate_risk(
    exposure: float,
    exploitability: float,
    impact: float,
    mitigation_strength: float,
    scanner_count: int,
) -> dict[str, float | str]:
    exposure = clamp(exposure)
    exploitability = clamp(exploitability)
    impact = clamp(impact)
    mitigation_strength = clamp(mitigation_strength)
    consensus = scanner_consensus_factor(scanner_count)

    risk = (exposure * exploitability * impact) * consensus * (1 - mitigation_strength)
    risk = clamp(risk)

    if risk >= 0.8:
        severity = "Critical"
    elif risk >= 0.6:
        severity = "High"
    elif risk >= 0.35:
        severity = "Medium"
    elif risk >= 0.15:
        severity = "Low"
    else:
        severity = "Informational"

    return {
        "risk": round(risk, 4),
        "severity": severity,
        "consensus_factor": consensus,
        "equation": "Risk = (Exposure × Exploitability × Impact) × Scanner Consensus × (1 − Mitigation Strength)",
    }
