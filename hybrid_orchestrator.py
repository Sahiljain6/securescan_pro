from __future__ import annotations

from typing import Any

from engine.feature_extractor import extract_features
from engine.risk_engine import calculate_risk_score, score_to_severity
from ml.vulnerability_classifier import VulnerabilityClassifier
from scanners.header_scanner import analyze_security_headers
from scanners.http_scanner import scan_http
from scanners.port_scanner import scan_common_ports
from scanners.redirect_scanner import analyze_redirects
from scanners.tls_scanner import scan_tls


class HybridVulnerabilityOrchestrator:
    _shared_classifier: VulnerabilityClassifier | None = None

    def __init__(self) -> None:
        if HybridVulnerabilityOrchestrator._shared_classifier is None:
            HybridVulnerabilityOrchestrator._shared_classifier = VulnerabilityClassifier()
        self.classifier = HybridVulnerabilityOrchestrator._shared_classifier

    def run(self, target_url: str) -> dict[str, Any]:
        http_result = scan_http(target_url)
        header_result = analyze_security_headers(http_result.get("response_headers", {}))
        tls_result = scan_tls(target_url)
        redirect_result = analyze_redirects(http_result.get("redirects", []))
        open_ports = scan_common_ports(target_url)

        merged = {
            "header_score": header_result["header_score"],
            "open_ports": open_ports,
            "redirects": redirect_result["redirect_count"],
            "tls_security_score": tls_result["tls_security_score"],
            "response_time": http_result.get("response_time", 0.0),
        }
        features = extract_features(merged)
        ml = self.classifier.classify(features)

        risk_score = calculate_risk_score(
            header_score=header_result["header_score"],
            open_ports=len(open_ports),
            redirect_count=redirect_result["redirect_count"],
            tls_issues=tls_result.get("tls_issues", 0),
        )
        severity = score_to_severity(risk_score)

        findings = self._build_findings(target_url, header_result["missing_headers"], open_ports, tls_result, redirect_result)
        dashboard_data = self._build_dashboard_data(severity, header_result["missing_headers"], open_ports, findings, risk_score)

        json_report = {
            "risk_score": risk_score,
            "severity": severity,
            "missing_headers": header_result["missing_headers"],
            "open_ports": open_ports,
            "tls_status": tls_result.get("tls_status", "unknown"),
            "redirects": redirect_result["redirect_count"],
        }

        return {
            "architecture": "Offline Passive Scanner -> Feature Extraction -> RandomForest -> Risk Engine -> Dashboard",
            "scanner_outputs": {
                "http": http_result,
                "headers": header_result,
                "tls": tls_result,
                "redirects": redirect_result,
                "ports": open_ports,
            },
            "scanner_status": {
                "http": "ok" if not http_result.get("error") else "degraded",
                "headers": "ok",
                "tls": "ok" if tls_result.get("tls_status") != "unknown" else "degraded",
                "redirects": "ok",
                "ports": "ok",
            },
            "findings": findings,
            "threat_intel": {},
            "dashboard_data": dashboard_data,
            "ai_analysis": {
                "engine": "Offline-RandomForest",
                "summary": f"Passive scan classified target risk as {severity} with ML estimate {ml['severity']}.",
                "model_confidence": ml["model_confidence"],
            },
            "scanner_ml_summary": {
                "feature_vector": features["feature_vector"],
                "risk_band": ml["severity"],
                "score": risk_score,
            },
            "metrics": {
                "vulnerabilities_by_scanner": {"Offline Passive Engine": len(findings)},
                "owasp_breakdown": {"Security Misconfiguration": len(findings)},
                "severity_distribution": dashboard_data["severity_distribution"],
                "severity_heatmap": dashboard_data["heatmap"],
                "confidence_aggregation": {severity: ml["model_confidence"]},
                "risk_score": risk_score,
            },
            "json_report": json_report,
        }

    @staticmethod
    def _build_findings(
        target_url: str,
        missing_headers: list[str],
        open_ports: list[int],
        tls_result: dict[str, Any],
        redirect_result: dict[str, Any],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for header in missing_headers:
            findings.append({"vulnerability": f"Missing {header}", "severity": "Medium", "endpoint": target_url})
        for port in open_ports:
            findings.append({"vulnerability": f"Open Port {port}", "severity": "Medium", "endpoint": target_url})
        for issue in tls_result.get("issues", []):
            findings.append({"vulnerability": issue.replace("_", " ").title(), "severity": "High", "endpoint": target_url})
        if redirect_result.get("multiple_redirects"):
            findings.append({"vulnerability": "Multiple Redirects", "severity": "Low", "endpoint": target_url})
        if redirect_result.get("redirect_loop"):
            findings.append({"vulnerability": "Redirect Loop Detected", "severity": "High", "endpoint": target_url})
        return findings

    @staticmethod
    def _build_dashboard_data(
        severity: str,
        missing_headers: list[str],
        open_ports: list[int],
        findings: list[dict[str, Any]],
        risk_score: float,
    ) -> dict[str, Any]:
        missing_headers_chart = {header: 1 for header in missing_headers} or {"None Missing": 1}
        open_ports_chart = {str(port): 1 for port in open_ports} or {"No Open Ports": 1}

        heatmap = {}
        for finding in findings:
            key = f"Passive::{finding.get('severity', 'Low')}"
            heatmap[key] = heatmap.get(key, 0) + 1

        return {
            "vulnerabilities": findings,
            "severity_distribution": {severity: 1},
            "missing_headers": missing_headers_chart,
            "open_ports": open_ports_chart,
            "scanner_comparison": {"Offline Passive Engine": len(findings) or 1},
            "owasp_categories": {"Security Misconfiguration": len(findings) or 1},
            "heatmap": heatmap or {"Passive::Low": 1},
            "risk_score": risk_score,
            "message": "Offline passive analysis completed.",
        }
