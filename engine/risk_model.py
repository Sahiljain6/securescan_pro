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

    normalized_risk = (exposure * exploitability * impact) * consensus * (1 - mitigation_strength)
    normalized_risk = clamp(normalized_risk)
    cvss_score = round(normalized_risk * 10, 2)

    if cvss_score >= 9.0:
        severity = "Critical"
    elif cvss_score >= 7.0:
        severity = "High"
    elif cvss_score >= 4.0:
        severity = "Medium"
    elif cvss_score >= 0.1:
        severity = "Low"
    else:
        severity = "Informational"

    return {
        "risk": round(normalized_risk, 4),
        "cvss_score": cvss_score,
        "severity": severity,
        "consensus_factor": consensus,
        "equation": "Risk = (Exposure × Exploitability × Impact) × ScannerConsensusFactor × (1 − MitigationStrength)",
    }
