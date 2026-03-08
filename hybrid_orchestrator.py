from __future__ import annotations

from collections import Counter
from typing import Any

from engine.risk_model import calculate_risk
from engine.vulnerability_aggregator import VulnerabilityAggregator
from ml.vulnerability_classifier import VulnerabilityClassifier
from scanners import BurpScanner, NiktoScanner, ZAPScanner


class HybridVulnerabilityOrchestrator:
    def __init__(self) -> None:
        self.zap = ZAPScanner()
        self.nikto = NiktoScanner()
        self.burp = BurpScanner()
        self.aggregator = VulnerabilityAggregator()
        self.classifier = VulnerabilityClassifier()

    def run(self, target_url: str) -> dict[str, Any]:
        scanner_outputs = [
            self.zap.run(target_url),
            self.nikto.run(target_url),
            self.burp.run(target_url),
        ]
        aggregated = self.aggregator.aggregate(scanner_outputs)

        enriched_findings = []
        for finding in aggregated["findings"]:
            ml_result = self.classifier.classify(finding)
            risk_result = calculate_risk(
                exposure=0.85,
                exploitability=finding.get("confidence", 0.6),
                impact=self._impact_from_severity(ml_result["severity"]),
                mitigation_strength=0.3,
                scanner_count=int(finding.get("scanner_count", 1)),
            )
            enriched_findings.append({**finding, "ml": ml_result, "risk": risk_result})

        return {
            "architecture": "Recon -> Multi-Scanner -> Aggregation -> ML Classifier -> Risk Engine -> Dashboard",
            "scanner_outputs": scanner_outputs,
            "findings": enriched_findings,
            "metrics": self._build_metrics(enriched_findings),
        }

    @staticmethod
    def _impact_from_severity(severity: str) -> float:
        mapping = {"Critical": 0.95, "High": 0.8, "Medium": 0.6, "Low": 0.35, "Informational": 0.15}
        return mapping.get(severity, 0.5)

    @staticmethod
    def _build_metrics(findings: list[dict[str, Any]]) -> dict[str, Any]:
        by_scanner = Counter()
        by_owasp = Counter()
        severity_heatmap = Counter()

        for finding in findings:
            scanners = [part.strip() for part in str(finding.get("scanner", "Unknown")).split(",")]
            for scanner in scanners:
                by_scanner[scanner] += 1
            by_owasp[finding.get("owasp_category", "Uncategorized")] += 1
            severity_heatmap[f"{finding.get('owasp_category', 'Uncategorized')}:{finding.get('ml', {}).get('severity', 'Low')}"] += 1

        return {
            "vulnerabilities_by_scanner": dict(by_scanner),
            "owasp_breakdown": dict(by_owasp),
            "severity_heatmap": dict(severity_heatmap),
            "scanner_comparison": {
                "max_coverage_scanner": max(by_scanner, key=by_scanner.get) if by_scanner else "N/A",
                "total_vulnerabilities": sum(by_scanner.values()),
            },
        }
