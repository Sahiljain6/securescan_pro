from __future__ import annotations

from urllib.parse import urlparse

from securescan_v5.models import DomainAssessment, HttpObservation, ValidationTrace


def _trace(baseline: HttpObservation | None, probe: HttpObservation | None, normalized: dict, delta: dict, correlated: dict) -> ValidationTrace:
    return ValidationTrace(
        baseline_capture={
            "status": baseline.status_code if baseline else 0,
            "length": len(baseline.body) if baseline else 0,
            "latency_ms": baseline.duration_ms if baseline else 0,
        },
        non_destructive_probe={
            "status": probe.status_code if probe else 0,
            "length": len(probe.body) if probe else 0,
            "latency_ms": probe.duration_ms if probe else 0,
        },
        error_normalization=normalized,
        behavioral_delta=delta,
        correlated_evidence_scoring=correlated,
    )


def broken_access_control(baseline, probe, normalized, delta, correlated, mitigation) -> DomainAssessment:
    protected = baseline.status_code in {401, 403, 302} if baseline else False
    evidence = [
        {"name": "Baseline access-control response", "score": 0.25 if protected else 0.8, "reliability": 0.7, "weight": 1.2},
        {"name": "Behavioral delta on probe", "score": 0.7 if delta["status_changed"] else 0.3, "reliability": 0.6, "weight": 1.0},
        {"name": "Mitigation header coverage", "score": 1 - mitigation["coverage"], "reliability": 0.75, "weight": 1.0},
    ]
    return DomainAssessment(
        domain="Broken Access Control",
        summary="Passive endpoint behavior and response controls indicate access boundary posture.",
        evidence=evidence,
        trace=_trace(baseline, probe, normalized, delta, correlated),
        mitigation_signals=mitigation,
    )


def cryptographic_failures(baseline, probe, normalized, delta, correlated, mitigation, target_url: str) -> DomainAssessment:
    parsed = urlparse(target_url)
    tls_score = 1.0 if parsed.scheme == "https" else 0.2
    evidence = [
        {"name": "HTTPS transport usage", "score": tls_score, "reliability": 0.9, "weight": 1.2},
        {"name": "Strict transport security header", "score": 1.0 if "Strict-Transport-Security" in (baseline.headers if baseline else {}) else 0.2, "reliability": 0.85, "weight": 1.0},
        {"name": "Content confidentiality indicators", "score": mitigation["coverage"], "reliability": 0.6, "weight": 0.6},
    ]
    return DomainAssessment(
        domain="Cryptographic Failures",
        summary="Transport and header-based cryptographic controls were measured using passive checks.",
        evidence=evidence,
        trace=_trace(baseline, probe, normalized, delta, correlated),
        mitigation_signals=mitigation,
    )


def injection(baseline, probe, normalized, delta, correlated, mitigation) -> DomainAssessment:
    reflected = "securescan_v5_reflection_marker" in (probe.body.lower() if probe else "")
    evidence = [
        {"name": "Reflection marker behavior", "score": 0.85 if reflected else 0.2, "reliability": 0.75, "weight": 1.1},
        {"name": "Normalized parser/database error patterns", "score": min(1.0, normalized["normalized_error_count"] / 3), "reliability": 0.8, "weight": 1.2},
        {"name": "Status and body deltas", "score": 0.8 if delta["status_changed"] or delta["delta_ratio"] > 0.25 else 0.25, "reliability": 0.7, "weight": 1.0},
    ]
    return DomainAssessment(
        domain="Injection",
        summary="Non-destructive parameter probes identified reflection and error-handling anomalies.",
        evidence=evidence,
        trace=_trace(baseline, probe, normalized, delta, correlated),
        mitigation_signals=mitigation,
    )


def security_misconfiguration(baseline, probe, normalized, delta, correlated, mitigation) -> DomainAssessment:
    evidence = [
        {"name": "Defensive header control coverage", "score": 1 - mitigation["coverage"], "reliability": 0.95, "weight": 1.3},
        {"name": "Server error hygiene", "score": 0.75 if not normalized["has_server_error"] else 0.3, "reliability": 0.65, "weight": 0.8},
        {"name": "Behavior stability", "score": 0.6 if delta["delta_ratio"] < 0.15 else 0.35, "reliability": 0.6, "weight": 0.7},
    ]
    return DomainAssessment(
        domain="Security Misconfiguration",
        summary="Configuration resilience was inferred from security headers and error hygiene patterns.",
        evidence=evidence,
        trace=_trace(baseline, probe, normalized, delta, correlated),
        mitigation_signals=mitigation,
    )


def authentication_failures(baseline, probe, normalized, delta, correlated, mitigation, session_mitigation) -> DomainAssessment:
    evidence = [
        {"name": "Session cookie defenses", "score": 1 - session_mitigation["strength"], "reliability": 0.85, "weight": 1.2},
        {"name": "Authentication response consistency", "score": 0.7 if delta["status_changed"] else 0.35, "reliability": 0.6, "weight": 0.8},
        {"name": "Security control fallback coverage", "score": 1 - mitigation["coverage"], "reliability": 0.7, "weight": 0.9},
    ]
    combined = {**mitigation, "session": session_mitigation}
    return DomainAssessment(
        domain="Authentication Failures",
        summary="Authentication and session management posture assessed from passive control telemetry.",
        evidence=evidence,
        trace=_trace(baseline, probe, normalized, delta, correlated),
        mitigation_signals=combined,
    )
