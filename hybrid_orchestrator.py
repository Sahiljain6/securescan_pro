from __future__ import annotations

import os
from collections import Counter
from typing import Any
from urllib.parse import urlparse

from engine.aggregator import VulnerabilityAggregator
from engine.risk_model import calculate_risk
from intel import NVDLookup, SecurityHeadersLookup, ShodanLookup, VirusTotalLookup
from ml.vulnerability_classifier import VulnerabilityClassifier
from scanners import BurpScanner, NiktoScanner, ZAPScanner


class HybridVulnerabilityOrchestrator:
    def __init__(self) -> None:
        self.zap = ZAPScanner()
        self.nikto = NiktoScanner()
        self.burp = BurpScanner()
        self.aggregator = VulnerabilityAggregator()
        self.classifier = VulnerabilityClassifier()
        self.nvd = NVDLookup(api_key=os.getenv("NVD_API_KEY"))
        self.virustotal = VirusTotalLookup(api_key=os.getenv("VIRUSTOTAL_API_KEY"))
        self.security_headers = SecurityHeadersLookup(api_key=os.getenv("SECURITY_HEADERS_API_KEY"))
        self.shodan = ShodanLookup(api_key=os.getenv("SHODAN_API_KEY"))

    def run(self, target_url: str) -> dict[str, Any]:
        scanner_outputs = [self.zap.run(target_url), self.nikto.run(target_url), self.burp.run(target_url)]
        aggregated = self.aggregator.aggregate(scanner_outputs)

        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""

        enriched_findings = []
        for finding in aggregated["findings"]:
            ml_result = self.classifier.classify(finding)
            intel_result = self.nvd.lookup(finding.get("vulnerability", ""))
            cves = intel_result.get("cves", [])
            cvss_impact = self._impact_from_cvss(cves)
            risk_result = calculate_risk(
                exposure=0.85,
                exploitability=finding.get("confidence", 0.6),
                impact=cvss_impact or self._impact_from_severity(ml_result["severity"]),
                mitigation_strength=0.3,
                scanner_count=int(finding.get("scanner_count", 1)),
            )
            enriched_findings.append(
                {
                    **finding,
                    "ml": ml_result,
                    "risk": risk_result,
                    "intel": {
                        "cve_ids": [entry.get("cve_id") for entry in cves if entry.get("cve_id")],
                        "cvss_scores": [entry.get("cvss_base_score") for entry in cves if entry.get("cvss_base_score") is not None],
                        "nvd_status": intel_result.get("status", "unknown"),
                    },
                }
            )

        threat_intel = {
            "virustotal": self.virustotal.domain_reputation(hostname) if hostname else {"status": "skipped"},
            "security_headers": self.security_headers.evaluate(hostname) if hostname else {"status": "skipped"},
            "shodan": self.shodan.lookup_host(hostname) if hostname else {"status": "skipped"},
        }

        dashboard_data = self.aggregator.build_dashboard_payload(enriched_findings)

        return {
            "architecture": "Recon -> Multi-Scanner -> Aggregation -> Threat Intel Enrichment -> ML Classifier -> Risk Engine -> Dashboard",
            "scanner_outputs": scanner_outputs,
            "scanner_status": aggregated["scanner_status"],
            "findings": enriched_findings,
            "threat_intel": threat_intel,
            "dashboard_data": dashboard_data,
            "metrics": self._build_metrics(enriched_findings, dashboard_data),
        }

    @staticmethod
    def _impact_from_severity(severity: str) -> float:
        mapping = {"Critical": 0.95, "High": 0.8, "Medium": 0.6, "Low": 0.35, "Informational": 0.15}
        return mapping.get(severity, 0.5)

    @staticmethod
    def _impact_from_cvss(cves: list[dict[str, Any]]) -> float:
        scores = [float(entry.get("cvss_base_score")) for entry in cves if entry.get("cvss_base_score") is not None]
        if not scores:
            return 0.0
        return min(1.0, max(scores) / 10.0)

    @staticmethod
    def _build_metrics(findings: list[dict[str, Any]], dashboard_data: dict[str, Any]) -> dict[str, Any]:
        confidence_by_severity = Counter()
        severity_counts = Counter([item.get("ml", {}).get("severity", "Low") for item in findings])
        for finding in findings:
            severity = finding.get("ml", {}).get("severity", "Low")
            confidence_by_severity[severity] += float(finding.get("confidence", 0.0))

        confidence_aggregation = {
            severity: round(confidence_by_severity[severity] / count, 3)
            for severity, count in severity_counts.items()
            if count > 0
        }

        return {
            "vulnerabilities_by_scanner": dashboard_data["scanner_comparison"],
            "owasp_breakdown": dashboard_data["owasp_categories"],
            "severity_distribution": dashboard_data["severity_distribution"],
            "severity_heatmap": dashboard_data.get("heatmap", {}),
            "confidence_aggregation": confidence_aggregation,
            "risk_score": dashboard_data["risk_score"],
        }
