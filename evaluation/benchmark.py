from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class BenchmarkResult:
    target: str
    detection_coverage: float
    false_positive_rate: float
    scanner_agreement_rate: float
    average_runtime_seconds: float


class BenchmarkSuite:
    """Research-oriented evaluation against vulnerable benchmarks (DVWA/Juice Shop)."""

    def evaluate(self, target: str, findings: list[dict[str, Any]], ground_truth: list[str], runtime_seconds: float) -> BenchmarkResult:
        truth_set = {name.lower() for name in ground_truth}
        detected_set = {item.get("vulnerability", "").lower() for item in findings}

        true_positives = len(truth_set.intersection(detected_set))
        false_positives = len([item for item in findings if item.get("vulnerability", "").lower() not in truth_set])

        coverage = true_positives / len(truth_set) if truth_set else 0.0
        fp_rate = false_positives / len(findings) if findings else 0.0
        agreement = self._scanner_agreement_rate(findings)

        return BenchmarkResult(
            target=target,
            detection_coverage=round(coverage, 3),
            false_positive_rate=round(fp_rate, 3),
            scanner_agreement_rate=round(agreement, 3),
            average_runtime_seconds=round(runtime_seconds, 2),
        )

    @staticmethod
    def _scanner_agreement_rate(findings: list[dict[str, Any]]) -> float:
        if not findings:
            return 0.0
        multi_detected = [item for item in findings if int(item.get("scanner_count", 1)) >= 2]
        return len(multi_detected) / len(findings)
