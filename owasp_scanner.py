from __future__ import annotations

from dataclasses import dataclass
import re
import socket
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, build_opener

from risk_model import calculate_risk, weighted_evidence_strength

SAFE_REFLECTION_MARKER = "SecureScanPro_v4_reflection_marker"
SAFE_SQL_TOKEN = "securescan_check_quote'"
SAFE_AUTH_PATHS = ["/admin", "/account", "/profile", "/login", "/auth"]
SQL_ERROR_TOKENS = ["sql syntax", "mysql", "sqlite", "postgresql", "odbc", "sqlstate", "database error"]


@dataclass
class HttpResult:
    status_code: int
    text: str
    headers: dict[str, str]
    url: str


@dataclass
class ScanContext:
    url: str
    baseline: HttpResult | None = None
    marker_probe: HttpResult | None = None
    sql_probe: HttpResult | None = None


def _safe_get(url: str) -> HttpResult | None:
    req = Request(url, headers={"User-Agent": "SecureScanPro/4.0 (Defensive-Academic)", "Accept": "text/html,*/*"})
    try:
        with build_opener().open(req, timeout=7) as response:  # noqa: S310
            body = response.read().decode("utf-8", errors="ignore")
            return HttpResult(response.getcode(), body, dict(response.headers.items()), response.geturl())
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore") if exc.fp else ""
        return HttpResult(exc.code, body, dict(exc.headers.items()) if exc.headers else {}, url)
    except (URLError, TimeoutError, OSError):
        return None


def _inject_query_value(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[key] = value
    query = urlencode(params)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))


def _tls_health(hostname: str | None) -> dict[str, Any]:
    if not hostname:
        return {"validated": False, "reason": "missing_hostname"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
        return {"validated": True, "not_after": cert.get("notAfter", "unknown")}
    except Exception as exc:  # noqa: BLE001
        return {"validated": False, "reason": str(exc)}


def _shared_stage_data(ctx: ScanContext) -> dict[str, Any]:
    baseline = _safe_get(ctx.url)
    ctx.baseline = baseline
    marker_probe = _safe_get(_inject_query_value(ctx.url, "ss_reflect", SAFE_REFLECTION_MARKER))
    ctx.marker_probe = marker_probe
    sql_probe = _safe_get(_inject_query_value(ctx.url, "ss_sql", SAFE_SQL_TOKEN))
    ctx.sql_probe = sql_probe

    parsed = urlparse(ctx.url)
    headers = dict(baseline.headers) if baseline else {}
    tls = _tls_health(parsed.hostname) if parsed.scheme == "https" else {"validated": False, "reason": "non_https"}

    return {
        "headers": headers,
        "tls": tls,
        "baseline_status": baseline.status_code if baseline else 0,
        "probe_status": marker_probe.status_code if marker_probe else 0,
        "sql_status": sql_probe.status_code if sql_probe else 0,
        "baseline_len": len(baseline.text) if baseline else 0,
        "probe_len": len(marker_probe.text) if marker_probe else 0,
        "sql_len": len(sql_probe.text) if sql_probe else 0,
    }


def _domain_finding(domain: str, summary: str, stages: list[dict[str, Any]], evidence: list[dict[str, Any]], exposure: float, exploitability: float, mitigation_strength: float, contradictory_signals: int = 0) -> dict[str, Any]:
    evidence_strength = weighted_evidence_strength(evidence)
    risk = calculate_risk(
        exposure=exposure,
        exploitability=exploitability,
        mitigation_strength=mitigation_strength,
        evidence_strength=evidence_strength,
        contradictory_signals=contradictory_signals,
        stage_coverage=min(1.0, len(stages) / 4),
    )

    return {
        "domain": domain,
        "summary": summary,
        "risk_equation": "Risk = Exposure × Exploitability × (1 − Mitigation Strength)",
        "risk_inputs": {
            "exposure": round(exposure, 3),
            "exploitability": round(exploitability, 3),
            "mitigation_strength": round(mitigation_strength, 3),
            "evidence_strength": round(evidence_strength, 3),
        },
        "risk_output": risk,
        "confidence": risk["confidence"],
        "severity": risk["severity"],
        "evidence": evidence,
        "stages": stages,
        "false_positive_controls": {
            "contradictory_signals": contradictory_signals,
            "suppression_factor": risk["false_positive_factor"],
        },
    }


def _broken_access_control(ctx: ScanContext, shared: dict[str, Any]) -> dict[str, Any]:
    auth_paths = [urlparse(ctx.url)._replace(path=p, query="").geturl() for p in SAFE_AUTH_PATHS]
    observed = []
    protected_count = 0
    for path in auth_paths[:3]:
        res = _safe_get(path)
        status = res.status_code if res else 0
        observed.append({"path": path, "status": status})
        if status in {401, 403, 302}:
            protected_count += 1

    stages = [
        {"stage": "BAC-1 Passive endpoint profiling", "observed_paths": observed},
        {"stage": "BAC-2 Access-control response patterning", "protected_ratio": round(protected_count / max(1, len(observed)), 3)},
        {"stage": "BAC-3 Session/cookie posture", "set_cookie_present": "Set-Cookie" in shared["headers"]},
        {"stage": "BAC-4 Mitigation-aware scoring", "controls_present": protected_count >= 2},
    ]
    evidence = [
        {"name": "Protected endpoint responses", "score": protected_count / max(1, len(observed)), "reliability": 0.9, "weight": 1.2},
        {"name": "Cookie hardening visibility", "score": 1.0 if "Set-Cookie" in shared["headers"] else 0.45, "reliability": 0.7, "weight": 0.8},
    ]
    return _domain_finding(
        "Broken Access Control",
        "Passive access-control indicators were evaluated through status-code behavior on common sensitive paths.",
        stages,
        evidence,
        exposure=0.7,
        exploitability=max(0.15, 1 - (protected_count / max(1, len(observed)))),
        mitigation_strength=protected_count / max(1, len(observed)),
    )


def _cryptographic_failures(ctx: ScanContext, shared: dict[str, Any]) -> dict[str, Any]:
    headers = shared["headers"]
    tls_ok = bool(shared["tls"].get("validated"))
    hsts = bool(headers.get("Strict-Transport-Security"))
    secure_cookie = "secure" in headers.get("Set-Cookie", "").lower()

    stages = [
        {"stage": "CRYPTO-1 TLS validation", "tls": shared["tls"]},
        {"stage": "CRYPTO-2 Transport policy review", "hsts_enabled": hsts},
        {"stage": "CRYPTO-3 Cookie confidentiality controls", "secure_cookie": secure_cookie},
        {"stage": "CRYPTO-4 Mitigation-aware scoring", "crypto_controls": sum([tls_ok, hsts, secure_cookie])},
    ]
    evidence = [
        {"name": "TLS certificate validity", "score": 1.0 if tls_ok else 0.0, "reliability": 0.95, "weight": 1.3},
        {"name": "HSTS policy", "score": 1.0 if hsts else 0.25, "reliability": 0.85, "weight": 1.0},
        {"name": "Secure cookie attribute", "score": 1.0 if secure_cookie else 0.35, "reliability": 0.8, "weight": 0.9},
    ]
    mitigation_strength = sum([tls_ok, hsts, secure_cookie]) / 3
    return _domain_finding(
        "Cryptographic Failures",
        "Transport and at-rest signaling controls were evaluated using passive TLS and header analysis.",
        stages,
        evidence,
        exposure=0.85,
        exploitability=1 - mitigation_strength,
        mitigation_strength=mitigation_strength,
    )


def _injection(ctx: ScanContext, shared: dict[str, Any]) -> dict[str, Any]:
    probe_body = (ctx.marker_probe.text if ctx.marker_probe else "")
    sql_body = (ctx.sql_probe.text if ctx.sql_probe else "")
    reflected = SAFE_REFLECTION_MARKER in probe_body
    sql_errors = [token for token in SQL_ERROR_TOKENS if token in sql_body.lower()]
    status_changed = shared["baseline_status"] != shared["sql_status"]

    stages = [
        {"stage": "INJ-1 Baseline response capture", "baseline_status": shared["baseline_status"], "baseline_length": shared["baseline_len"]},
        {"stage": "INJ-2 Safe reflection validation", "marker_reflected": reflected},
        {"stage": "INJ-3 Error-signature and differential analysis", "sql_error_tokens": sql_errors, "status_changed": status_changed},
        {"stage": "INJ-4 Mitigation-aware scoring", "encoding_and_header_controls": bool(shared["headers"].get("Content-Security-Policy"))},
    ]
    evidence = [
        {"name": "Reflection marker observation", "score": 1.0 if reflected else 0.2, "reliability": 0.75, "weight": 1.0},
        {"name": "SQL error token correlation", "score": min(1.0, len(sql_errors) / 3), "reliability": 0.8, "weight": 1.2},
        {"name": "Behavioral status delta", "score": 1.0 if status_changed else 0.3, "reliability": 0.65, "weight": 0.7},
    ]
    mitigation_strength = 1.0 if shared["headers"].get("Content-Security-Policy") else 0.35
    return _domain_finding(
        "Injection",
        "Non-destructive, parameter-safe probes were used to detect reflection and database error leakage patterns.",
        stages,
        evidence,
        exposure=0.9,
        exploitability=0.75 if (reflected or sql_errors or status_changed) else 0.25,
        mitigation_strength=mitigation_strength,
        contradictory_signals=1 if reflected and not sql_errors and not status_changed else 0,
    )


def _security_misconfiguration(ctx: ScanContext, shared: dict[str, Any]) -> dict[str, Any]:
    headers = shared["headers"]
    controls = {
        "content_security_policy": bool(headers.get("Content-Security-Policy")),
        "x_frame_options": bool(headers.get("X-Frame-Options")),
        "x_content_type_options": bool(headers.get("X-Content-Type-Options")),
        "referrer_policy": bool(headers.get("Referrer-Policy")),
    }
    missing = [name for name, present in controls.items() if not present]

    stages = [
        {"stage": "MISCONF-1 Header inventory", "observed_header_count": len(headers)},
        {"stage": "MISCONF-2 Defensive-control mapping", "controls": controls},
        {"stage": "MISCONF-3 Exposure inference", "missing_controls": missing},
        {"stage": "MISCONF-4 Mitigation-aware scoring", "control_coverage_ratio": round((len(controls) - len(missing)) / len(controls), 3)},
    ]
    evidence = [
        {"name": "Security header control coverage", "score": (len(controls) - len(missing)) / len(controls), "reliability": 0.95, "weight": 1.3},
        {"name": "Observed response hygiene", "score": 1.0 if shared["baseline_status"] < 500 else 0.3, "reliability": 0.7, "weight": 0.7},
    ]
    mitigation_strength = (len(controls) - len(missing)) / len(controls)
    return _domain_finding(
        "Security Misconfiguration",
        "Configuration posture was assessed by mapping observed headers to preventive controls.",
        stages,
        evidence,
        exposure=0.8,
        exploitability=1 - mitigation_strength,
        mitigation_strength=mitigation_strength,
    )


def _identification_auth_failures(ctx: ScanContext, shared: dict[str, Any]) -> dict[str, Any]:
    headers = shared["headers"]
    cookie_line = headers.get("Set-Cookie", "").lower()
    has_httponly = "httponly" in cookie_line
    has_samesite = "samesite" in cookie_line
    login_observable = any(path in (ctx.baseline.url if ctx.baseline else "") for path in ["login", "auth", "signin"])

    stages = [
        {"stage": "IAF-1 Authentication surface identification", "login_surface_observable": login_observable},
        {"stage": "IAF-2 Session token policy checks", "httponly": has_httponly, "samesite": has_samesite},
        {"stage": "IAF-3 Passive response behavior", "status_pattern": [shared["baseline_status"], shared["probe_status"]]},
        {"stage": "IAF-4 Mitigation-aware scoring", "session_controls": sum([has_httponly, has_samesite])},
    ]
    evidence = [
        {"name": "HttpOnly attribute", "score": 1.0 if has_httponly else 0.25, "reliability": 0.85, "weight": 1.0},
        {"name": "SameSite attribute", "score": 1.0 if has_samesite else 0.25, "reliability": 0.85, "weight": 1.0},
        {"name": "Auth surface discoverability", "score": 0.6 if login_observable else 0.4, "reliability": 0.6, "weight": 0.5},
    ]
    mitigation_strength = (sum([has_httponly, has_samesite])) / 2
    return _domain_finding(
        "Identification & Authentication Failures",
        "Session and authentication controls were reviewed through passive cookie and endpoint observations.",
        stages,
        evidence,
        exposure=0.75,
        exploitability=1 - mitigation_strength,
        mitigation_strength=mitigation_strength,
    )


def run_owasp_scan(url: str) -> dict[str, Any]:
    ctx = ScanContext(url=url)
    shared = _shared_stage_data(ctx)

    domain_findings = [
        _broken_access_control(ctx, shared),
        _cryptographic_failures(ctx, shared),
        _injection(ctx, shared),
        _security_misconfiguration(ctx, shared),
        _identification_auth_failures(ctx, shared),
    ]

    stages = [{"stage": "Shared Passive Collection", **shared}]
    for finding in domain_findings:
        stages.extend(finding["stages"])

    avg_conf = round(sum(f["confidence"] for f in domain_findings) / len(domain_findings), 1)
    return {
        "stages": stages,
        "findings": domain_findings,
        "domain_breakdown": [
            {
                "domain": item["domain"],
                "risk": item["risk_output"]["risk"],
                "severity": item["severity"],
                "confidence": item["confidence"],
            }
            for item in domain_findings
        ],
        "confidence_average": avg_conf,
    }
