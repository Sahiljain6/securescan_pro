from __future__ import annotations


class ConfidenceEngine:
    def calculate(self, evidence_score: float, stage_coverage: float, contradiction_penalty: float = 0.0) -> float:
        base = (0.6 * evidence_score) + (0.4 * stage_coverage)
        value = max(0.0, min(1.0, base - contradiction_penalty))
        return round(value * 100, 1)
