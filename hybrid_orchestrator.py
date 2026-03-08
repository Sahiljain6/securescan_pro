from __future__ import annotations

import os
from collections import Counter
from typing import Any
from urllib.parse import urlparse

from engine.risk_model import calculate_risk
from engine.vulnerability_aggregator import VulnerabilityAggregator
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
        scanner_outputs = [
            self.zap.run(target_url),
            self.nikto.run(target_url),
            self.burp.run(target_url),
        ]
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

        return {
            "architecture": "Recon -> Multi-Scanner -> Aggregation -> Threat Intel Enrichment -> ML Classifier -> Risk Engine -> Dashboard",
            "scanner_outputs": scanner_outputs,
            "findings": enriched_findings,
            "threat_intel": threat_intel,
            "metrics": self._build_metrics(enriched_findings),
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
        return min(1.0, (max(scores) / 10.0))

    @staticmethod
    def _build_metrics(findings: list[dict[str, Any]]) -> dict[str, Any]:
        by_scanner = Counter()
        by_owasp = Counter()
        severity_heatmap = Counter()
        confidence_by_severity = Counter()

        for finding in findings:
            scanners = finding.get("scanner_sources") or [part.strip() for part in str(finding.get("scanner", "Unknown")).split(",")]
            for scanner in scanners:
                by_scanner[scanner] += 1

            severity = finding.get("ml", {}).get("severity", "Low")
            owasp = finding.get("owasp_category", "Uncategorized")
            by_owasp[owasp] += 1
            severity_heatmap[f"{owasp}:{severity}"] += 1
            confidence_by_severity[severity] += float(finding.get("confidence", 0.0))

        severity_counts = Counter([item.get("ml", {}).get("severity", "Low") for item in findings])
        confidence_aggregation = {
            severity: round(confidence_by_severity[severity] / count, 3)
            for severity, count in severity_counts.items()
            if count > 0
        }

        return {
            "vulnerabilities_by_scanner": dict(by_scanner),
            "owasp_breakdown": dict(by_owasp),
            "severity_distribution": dict(severity_counts),
            "severity_heatmap": dict(severity_heatmap),
            "confidence_aggregation": confidence_aggregation,
            "scanner_comparison": {
                "max_coverage_scanner": max(by_scanner, key=by_scanner.get) if by_scanner else "N/A",
                "total_vulnerabilities": len(findings),
            },
        }
