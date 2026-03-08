from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

NAME_NORMALIZATION = {
    "sql injection": "SQL Injection",
    "cross-site scripting": "Cross-Site Scripting",
    "xss": "Cross-Site Scripting",
    "command injection": "Command Injection",
    "open redirect": "Open Redirect",
    "missing x-frame-options header": "Security Headers Missing",
    "missing content-security-policy": "Security Headers Missing",
    "server leaks version information": "Information Disclosure",
    "tls": "Cryptographic Weakness",
}

SEVERITY_NORMALIZATION = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
    "informational": "Informational",
}

SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}

OWASP_MAPPING = {
    "SQL Injection": "A03:2021 - Injection",
    "Cross-Site Scripting": "A03:2021 - Injection",
    "Command Injection": "A03:2021 - Injection",
    "Security Headers Missing": "A05:2021 - Security Misconfiguration",
    "Information Disclosure": "A05:2021 - Security Misconfiguration",
    "Cryptographic Weakness": "A02:2021 - Cryptographic Failures",
    "Broken Authentication": "A07:2021 - Identification and Authentication Failures",
    "Broken Access Control": "A01:2021 - Broken Access Control",
    "Open Redirect": "A10:2021 - Server-Side Request Forgery",
}


class VulnerabilityAggregator:
    """Merge scanner output into a normalized vulnerability model."""

    def aggregate(self, scanner_results: list[dict[str, Any]]) -> dict[str, Any]:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

        for scanner_result in scanner_results:
            for finding in scanner_result.get("findings", []):
                normalized = self._normalize_finding(finding)
                key = (normalized["vulnerability"], normalized["endpoint"])
                grouped[key].append(normalized)

        merged = [self._merge_group(findings) for findings in grouped.values()]
        merged.sort(key=lambda finding: (SEVERITY_ORDER.get(finding["severity"], 0), finding["consensus_score"]), reverse=True)

        return {
            "findings": merged,
            "scanner_status": {result.get("scanner", "Unknown"): result.get("status", "unknown") for result in scanner_results},
            "total_findings": len(merged),
        }

    def build_dashboard_payload(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        severity_distribution = Counter(finding["severity"] for finding in findings)
        scanner_comparison = Counter()
        owasp_categories = Counter(finding.get("owasp_category", "Uncategorized") for finding in findings)
        heatmap = Counter()

        for finding in findings:
            scanners = finding.get("scanner_sources") or [finding.get("scanner", "Unknown")]
            for scanner_name in scanners:
                scanner_comparison[scanner_name] += 1
            heatmap[f"{finding.get('owasp_category', 'Uncategorized')}::{finding['severity']}"] += 1

        if not findings:
            return {
                "vulnerabilities": [],
                "severity_distribution": {"Informational": 1},
                "scanner_comparison": {"No Findings": 1},
                "owasp_categories": {"No OWASP Mapping": 1},
                "heatmap": {"No Data::Informational": 1},
                "risk_score": 0,
                "message": "No vulnerabilities detected. Charts rendered with informational baseline.",
            }

        risk_score = round(
            sum(SEVERITY_ORDER.get(finding["severity"], 1) * float(finding.get("consensus_score", 0.0)) for finding in findings)
            / max(len(findings), 1)
            * 2,
            2,
        )

        return {
            "vulnerabilities": findings,
            "severity_distribution": dict(severity_distribution),
            "scanner_comparison": dict(scanner_comparison),
            "owasp_categories": dict(owasp_categories),
            "heatmap": dict(heatmap),
            "risk_score": max(0, min(10, risk_score)),
        }

    def _normalize_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        vulnerability = self._normalize_name((finding.get("vulnerability") or "Unknown finding").strip())
        endpoint = (finding.get("endpoint") or "").split("?")[0]
        severity = self._normalize_severity(finding.get("severity", "Informational"))
        confidence = min(max(float(finding.get("confidence", 0.5)), 0.0), 1.0)

        return {
            **finding,
            "vulnerability": vulnerability,
            "endpoint": endpoint,
            "severity": severity,
            "confidence": round(confidence, 3),
            "owasp_category": OWASP_MAPPING.get(vulnerability, "Uncategorized"),
        }

    def _merge_group(self, grouped_findings: list[dict[str, Any]]) -> dict[str, Any]:
        top = max(grouped_findings, key=lambda finding: SEVERITY_ORDER.get(finding["severity"], 1))
        scanners = sorted({finding.get("scanner", "Unknown") for finding in grouped_findings})
        avg_confidence = sum(item["confidence"] for item in grouped_findings) / len(grouped_findings)
        consensus_score = round(min(0.99, avg_confidence + (0.1 * (len(scanners) - 1))), 3)

        return {
            **top,
            "scanner": ", ".join(scanners),
            "scanner_sources": scanners,
            "scanner_count": len(scanners),
            "consensus_score": consensus_score,
            "confidence": consensus_score,
            "duplicates_merged": len(grouped_findings),
            "sources": grouped_findings,
        }

    @staticmethod
    def _normalize_name(raw_name: str) -> str:
        lowered = raw_name.lower()
        for needle, normalized in NAME_NORMALIZATION.items():
            if needle in lowered:
                return normalized
        return raw_name

    @staticmethod
    def _normalize_severity(raw_value: str) -> str:
        return SEVERITY_NORMALIZATION.get(str(raw_value).strip().lower(), "Informational")
