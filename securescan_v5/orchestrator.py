from __future__ import annotations

from typing import Any

from securescan_v5.domains.owasp_top5 import (
    authentication_failures,
    broken_access_control,
    cryptographic_failures,
    injection,
    security_misconfiguration,
)
from securescan_v5.engines.baseline_engine import BaselineEngine
from securescan_v5.engines.confidence_engine import ConfidenceEngine
from securescan_v5.engines.correlation_engine import CorrelationEngine
from securescan_v5.engines.mitigation_analyzer import MitigationAnalyzer
from securescan_v5.engines.risk_modeling_engine import RiskModelingEngine


class SecureScanV5:
    def __init__(self) -> None:
        self.baseline_engine = BaselineEngine()
        self.correlation_engine = CorrelationEngine()
        self.mitigation_analyzer = MitigationAnalyzer()
        self.confidence_engine = ConfidenceEngine()
        self.risk_engine = RiskModelingEngine()

    def _enrich_domain(self, assessment, exposure: float, exploitability: float, contradiction: float = 0.0) -> dict[str, Any]:
        correlated = self.correlation_engine.correlated_score(assessment.evidence)
        stage_coverage = 1.0
        confidence = self.confidence_engine.calculate(
            evidence_score=correlated["correlated_evidence"],
            stage_coverage=stage_coverage,
            contradiction_penalty=contradiction,
        )
        mitigation_strength = float(assessment.mitigation_signals.get("coverage", 0.2))
        risk = self.risk_engine.calculate(exposure, exploitability, mitigation_strength, confidence)
        return {
            "domain": assessment.domain,
            "summary": assessment.summary,
            "risk_equation": risk["equation"],
            "risk_inputs": {
                "exposure": round(exposure, 3),
                "exploitability": round(exploitability, 3),
                "mitigation": round(mitigation_strength, 3),
                "confidence": confidence,
            },
            "risk_output": risk,
            "confidence": confidence,
            "severity": risk["severity"],
            "evidence": assessment.evidence,
            "mitigation_signals": assessment.mitigation_signals,
            "stages": [
                {"stage": "Baseline capture", **assessment.trace.baseline_capture},
                {"stage": "Non-destructive probe", **assessment.trace.non_destructive_probe},
                {"stage": "Error normalization", **assessment.trace.error_normalization},
                {"stage": "Behavioral delta comparison", **assessment.trace.behavioral_delta},
                {"stage": "Correlated evidence scoring", **{**assessment.trace.correlated_evidence_scoring, **correlated}},
            ],
        }

    def run(self, url: str) -> dict[str, Any]:
        baseline = self.baseline_engine.fetch(url, "baseline_capture")
        probe_url = self.baseline_engine.inject_query(url, "ss_probe", "securescan_v5_reflection_marker")
        probe = self.baseline_engine.fetch(probe_url, "non_destructive_probe")

        normalized = self.correlation_engine.normalize_errors(probe)
        delta = self.correlation_engine.behavioral_delta(baseline, probe)
        mitigation = self.mitigation_analyzer.analyze_headers(baseline.headers if baseline else {})
        session_controls = self.mitigation_analyzer.analyze_session_controls(baseline.headers if baseline else {})

        domains = [
            broken_access_control(baseline, probe, normalized, delta, {}, mitigation),
            cryptographic_failures(baseline, probe, normalized, delta, {}, mitigation, url),
            injection(baseline, probe, normalized, delta, {}, mitigation),
            security_misconfiguration(baseline, probe, normalized, delta, {}, mitigation),
            authentication_failures(baseline, probe, normalized, delta, {}, mitigation, session_controls),
        ]

        profiles = {
            "Broken Access Control": (0.9, 0.7, 0.03),
            "Cryptographic Failures": (0.85, 0.6, 0.01),
            "Injection": (0.95, 0.75, 0.04),
            "Security Misconfiguration": (0.8, 0.65, 0.02),
            "Authentication Failures": (0.88, 0.7, 0.03),
        }

        findings = []
        all_stages = []
        for domain in domains:
            exposure, exploitability, contradiction = profiles[domain.domain]
            finding = self._enrich_domain(domain, exposure, exploitability, contradiction)
            findings.append(finding)
            all_stages.extend(finding["stages"])

        confidence_avg = round(sum(item["confidence"] for item in findings) / len(findings), 1)
        domain_breakdown = [
            {
                "domain": item["domain"],
                "risk": item["risk_output"]["weighted_risk"],
                "severity": item["severity"],
                "confidence": item["confidence"],
            }
            for item in findings
        ]

        return {
            "framework": "SecureScan Pro v5",
            "scan_model": "Defensive-only passive behavioral validation",
            "findings": findings,
            "stages": all_stages,
            "domain_breakdown": domain_breakdown,
            "confidence_average": confidence_avg,
            "risk_model": "Risk = Exposure × Exploitability × (1 − Mitigation), weighted by confidence",
            "limitations": [
                "No exploitation or aggressive attack payloads are executed.",
                "Results are behavioral and should be paired with authorized secure code review.",
                "Passive telemetry can miss deep business logic vulnerabilities.",
            ],
        }
