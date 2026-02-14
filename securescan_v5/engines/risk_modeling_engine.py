from __future__ import annotations


class RiskModelingEngine:
    """Risk = Exposure × Exploitability × (1 − Mitigation), weighted by confidence."""

    @staticmethod
    def classify(score: float) -> str:
        if score >= 0.7:
            return "Critical"
        if score >= 0.5:
            return "High"
        if score >= 0.3:
            return "Medium"
        if score >= 0.15:
            return "Low"
        return "Informational"

    def calculate(self, exposure: float, exploitability: float, mitigation: float, confidence: float) -> dict[str, float | str]:
        base_risk = max(0.0, min(1.0, exposure * exploitability * (1 - mitigation)))
        confidence_weight = confidence / 100
        weighted_risk = round(base_risk * confidence_weight, 4)
        return {
            "base_risk": round(base_risk, 4),
            "weighted_risk": weighted_risk,
            "confidence_weight": round(confidence_weight, 4),
            "severity": self.classify(weighted_risk),
            "equation": "Risk = Exposure × Exploitability × (1 − Mitigation) weighted by confidence",
        }
