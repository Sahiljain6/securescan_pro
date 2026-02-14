from __future__ import annotations

from securescan_v5.models import HttpObservation


class CorrelationEngine:
    """Normalizes response errors and computes behavioral deltas without exploitation."""

    SQL_TOKENS = ["sql syntax", "mysql", "sqlite", "postgresql", "sqlstate", "odbc", "database error"]

    def normalize_errors(self, probe: HttpObservation | None) -> dict[str, object]:
        if not probe:
            return {"error_tokens": [], "normalized_error_count": 0, "has_server_error": False}
        body = probe.body.lower()
        tokens = [token for token in self.SQL_TOKENS if token in body]
        return {
            "error_tokens": tokens,
            "normalized_error_count": len(tokens),
            "has_server_error": probe.status_code >= 500,
        }

    def behavioral_delta(self, baseline: HttpObservation | None, probe: HttpObservation | None) -> dict[str, object]:
        if not baseline or not probe:
            return {
                "status_changed": False,
                "length_delta": 0,
                "latency_delta_ms": 0,
                "delta_ratio": 0,
            }
        length_delta = len(probe.body) - len(baseline.body)
        baseline_len = max(1, len(baseline.body))
        return {
            "status_changed": baseline.status_code != probe.status_code,
            "length_delta": length_delta,
            "latency_delta_ms": round(probe.duration_ms - baseline.duration_ms, 2),
            "delta_ratio": round(abs(length_delta) / baseline_len, 3),
        }

    def correlated_score(self, evidence: list[dict[str, float]]) -> dict[str, float]:
        weighted = 0.0
        total = 0.0
        for item in evidence:
            weight = float(item.get("weight", 1.0))
            score = float(item.get("score", 0.0))
            reliability = float(item.get("reliability", 0.5))
            weighted += score * reliability * weight
            total += weight
        value = (weighted / total) if total else 0.0
        return {"correlated_evidence": round(value, 4), "evidence_items": len(evidence)}
