from __future__ import annotations

import os
from collections import Counter
from typing import Any
from urllib.parse import urlparse

from ai_security_engine import AISecurityEngine
from engine.aggregator import VulnerabilityAggregator
from engine.risk_model import calculate_risk
from intel import NVDLookup, SecurityHeadersLookup, ShodanLookup, VirusTotalLookup
from ml.vulnerability_classifier import VulnerabilityClassifier
from ml_model import model
from scanner import run_defensive_web_checks
from scanners import BurpScanner, NiktoScanner, ZAPScanner


class HybridVulnerabilityOrchestrator:
    _shared_classifier: VulnerabilityClassifier | None = None

    def __init__(self) -> None:
        self.zap = ZAPScanner()
        self.nikto = NiktoScanner()
        self.burp = BurpScanner()
        self.aggregator = VulnerabilityAggregator()
        if HybridVulnerabilityOrchestrator._shared_classifier is None:
            HybridVulnerabilityOrchestrator._shared_classifier = VulnerabilityClassifier()
        self.classifier = HybridVulnerabilityOrchestrator._shared_classifier
        self.ai_engine = AISecurityEngine()
        self.nvd = NVDLookup(api_key=os.getenv("NVD_API_KEY"))
        self.virustotal = VirusTotalLookup(api_key=os.getenv("VIRUSTOTAL_API_KEY"))
        self.security_headers = SecurityHeadersLookup(api_key=os.getenv("SECURITY_HEADERS_API_KEY"))
        self.shodan = ShodanLookup(api_key=os.getenv("SHODAN_API_KEY"))

    def run(self, target_url: str) -> dict[str, Any]:
        scanner_outputs = [
            run_defensive_web_checks(target_url),
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
            confidence = float(max(finding.get("confidence", 0.6), ml_result.get("model_confidence", 0.6)))
            risk_result = calculate_risk(
                exposure=0.85,
                exploitability=finding.get("confidence", 0.6),
                impact=cvss_impact or self._impact_from_severity(ml_result["severity"]),
                confidence=confidence,
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
        ai_analysis = self.ai_engine.analyze_vulnerability(enriched_findings)

        scanner_ml_summary = model.classify_scanner_risk(ai_analysis.get("vulnerabilities", enriched_findings))

        dashboard_data["severity_distribution"] = ai_analysis.get("severity_distribution", dashboard_data.get("severity_distribution", {}))
        dashboard_data["owasp_categories"] = ai_analysis.get("owasp_categories", dashboard_data.get("owasp_categories", {}))
        dashboard_data["risk_score"] = ai_analysis.get("risk_score", dashboard_data.get("risk_score", 0))
        dashboard_data["ai_analysis"] = ai_analysis.get("ai_analysis", {})

        return {
            "architecture": "Recon -> Passive Checks -> Multi-Scanner -> Aggregation -> Threat Intel -> ML Feature Extraction -> AI Risk Analysis -> Reporting",
            "scanner_outputs": scanner_outputs,
            "scanner_status": aggregated["scanner_status"],
            "findings": ai_analysis.get("vulnerabilities", enriched_findings),
            "threat_intel": threat_intel,
            "dashboard_data": dashboard_data,
            "ai_analysis": ai_analysis.get("ai_analysis", {}),
            "scanner_ml_summary": scanner_ml_summary,
            "metrics": self._build_metrics(ai_analysis.get("vulnerabilities", enriched_findings), dashboard_data),
            "json_report": {
                "vulnerabilities": ai_analysis.get("vulnerabilities", enriched_findings),
                "severity_distribution": dashboard_data.get("severity_distribution", {}),
                "owasp_categories": dashboard_data.get("owasp_categories", {}),
                "risk_score": dashboard_data.get("risk_score", 0),
                "ai_analysis": {**ai_analysis.get("ai_analysis", {}), "ml_summary": scanner_ml_summary},
            },
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
        severity_counts = Counter([item.get("severity") or item.get("ml", {}).get("severity", "Low") for item in findings])
        for finding in findings:
            severity = finding.get("severity") or finding.get("ml", {}).get("severity", "Low")
            confidence = float(finding.get("risk", {}).get("confidence", finding.get("confidence", 0.0)))
            confidence_by_severity[severity] += confidence

        confidence_aggregation = {
            severity: round(confidence_by_severity[severity] / count, 3)
            for severity, count in severity_counts.items()
            if count > 0
        }

        return {
            "vulnerabilities_by_scanner": dashboard_data.get("scanner_comparison", {}),
            "owasp_breakdown": dashboard_data.get("owasp_categories", {}),
            "severity_distribution": dashboard_data.get("severity_distribution", {}),
            "severity_heatmap": dashboard_data.get("heatmap", {}),
            "confidence_aggregation": confidence_aggregation,
            "risk_score": dashboard_data.get("risk_score", 0),
        }
