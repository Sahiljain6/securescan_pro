from __future__ import annotations

from dataclasses import dataclass
import html
import re
import socket
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

SAFE_MARKER = "SecureScanPro_reflection_check"
SAFE_REFLECTION_PAYLOAD = f"<script>{SAFE_MARKER}</script>"
SAFE_SQL_PAYLOAD = "1'"
SQL_ERROR_TOKENS = ["sql syntax", "mysql", "sqlite", "postgresql", "odbc", "database error", "sqlstate"]


@dataclass
class HttpResult:
    status_code: int
    text: str
    headers: dict[str, str]
    url: str
    redirect_chain: list[str]


@dataclass
class StageContext:
    url: str
    baseline: HttpResult | None = None
    probe: HttpResult | None = None
    sql_probe: HttpResult | None = None
    marker: str = SAFE_REFLECTION_PAYLOAD
    stages: list[dict[str, Any]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.stages is None:
            self.stages = []


class _TrackingRedirectHandler(HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self.chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        self.chain.append(f"{code}:{newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _inject_query_value(url: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params["sspro_test"] = value
    query = urlencode(params)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))


def _safe_get(url: str) -> HttpResult | None:
    handler = _TrackingRedirectHandler()
    opener = build_opener(handler)
    req = Request(url, headers={"User-Agent": "SecureScanPro/3.0", "Accept": "text/html,*/*"})
    try:
        with opener.open(req, timeout=7) as response:  # noqa: S310
            body = response.read().decode("utf-8", errors="ignore")
            return HttpResult(
                status_code=response.getcode(),
                text=body,
                headers=dict(response.headers.items()),
                url=response.geturl(),
                redirect_chain=handler.chain,
            )
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore") if exc.fp else ""
        return HttpResult(exc.code, body, dict(exc.headers.items()) if exc.headers else {}, url, handler.chain)
    except (URLError, TimeoutError, OSError):
        return None


def _tls_validation(hostname: str | None) -> dict[str, Any]:
    if not hostname:
        return {"valid": False, "reason": "invalid_hostname"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
        return {"valid": True, "not_after": cert.get("notAfter", "unknown")}
    except Exception as exc:  # noqa: BLE001
        return {"valid": False, "reason": str(exc)}


def _reflection_context(body: str, marker: str) -> str:
    if marker not in body:
        return "none"
    idx = body.find(marker)
    window = body[max(0, idx - 140) : idx + len(marker) + 140].lower()

    if re.search(r"<script[^>]*>[^<]*" + re.escape(marker.lower()), window):
        return "script_block"
    if re.search(r"\w+=['\"][^'\"]*" + re.escape(marker.lower()), window):
        return "attribute"
    return "html"


def _detect_encoding(body: str, payload: str) -> dict[str, bool]:
    html_encoded = html.escape(payload) in body
    js_escaped = payload.replace("<", "\\x3c").replace(">", "\\x3e") in body
    return {"html_encoded": html_encoded, "js_escaped": js_escaped}


def _severity(score: float) -> str:
    if score >= 8.5:
        return "Critical"
    if score >= 6.5:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 1.5:
        return "Low"
    return "Informational"


def _build_finding(vulnerability: str, exploitability_score: float, confidence: float, mitigation_present: bool, explanation: str) -> dict[str, Any]:
    adjusted = exploitability_score * (0.78 if mitigation_present else 1.0)
    adjusted = max(0.0, round(adjusted, 2))
    confidence = max(1.0, min(99.0, confidence))
    return {
        "vulnerability": vulnerability,
        "exploitability_score": adjusted,
        "confidence": round(confidence, 1),
        "severity": _severity(adjusted),
        "mitigation_present": mitigation_present,
        "explanation": explanation,
    }


def _stage1_passive_recon(ctx: StageContext) -> None:
    baseline = _safe_get(ctx.url)
    ctx.baseline = baseline
    parsed = urlparse(ctx.url)

    headers = dict(baseline.headers) if baseline else {}
    set_cookie_lines = []
    if baseline:
        raw_cookie = baseline.headers.get("Set-Cookie")
        if raw_cookie:
            set_cookie_lines = [line.strip() for line in raw_cookie.split(",")]

    cookie_flags = {"secure": 0, "httponly": 0, "samesite": 0}
    for line in set_cookie_lines:
        lower = line.lower()
        cookie_flags["secure"] += int("secure" in lower)
        cookie_flags["httponly"] += int("httponly" in lower)
        cookie_flags["samesite"] += int("samesite=" in lower)

    tls = _tls_validation(parsed.hostname) if parsed.scheme == "https" else {"valid": False, "reason": "non_https"}

    ctx.stages.append(
        {
            "stage": "Stage 1: Passive reconnaissance",
            "headers_collected": sorted(list(headers.keys()))[:20],
            "tls_validation": tls,
            "redirect_chain": baseline.redirect_chain if baseline else [],
            "cookie_security_flags": cookie_flags,
        }
    )


def _stage2_reflection_detection(ctx: StageContext) -> None:
    probe = _safe_get(_inject_query_value(ctx.url, ctx.marker))
    ctx.probe = probe
    body = probe.text if probe else ""
    reflected = ctx.marker in body
    context = _reflection_context(body, SAFE_MARKER)
    ctx.stages.append(
        {
            "stage": "Stage 2: Reflection detection",
            "parameter_reflection": reflected,
            "context_classification": context,
        }
    )


def _stage3_encoding_validation(ctx: StageContext) -> None:
    body = ctx.probe.text if ctx.probe else ""
    encoding = _detect_encoding(body, ctx.marker)
    ctx.stages.append(
        {
            "stage": "Stage 3: Encoding validation",
            "html_encoding_detected": encoding["html_encoded"],
            "javascript_escaping_detected": encoding["js_escaped"],
        }
    )


def _stage4_mitigation_awareness(ctx: StageContext) -> None:
    headers = dict(ctx.baseline.headers) if ctx.baseline else {}
    mitigations = {
        "csp": bool(headers.get("Content-Security-Policy")),
        "x_frame_options": bool(headers.get("X-Frame-Options")),
        "hsts": bool(headers.get("Strict-Transport-Security")),
    }
    ctx.stages.append(
        {
            "stage": "Stage 4: Mitigation awareness",
            "mitigations": mitigations,
            "mitigation_count": sum(int(v) for v in mitigations.values()),
        }
    )


def _stage5_behavioral_validation(ctx: StageContext) -> None:
    baseline = ctx.baseline
    sql_probe = _safe_get(_inject_query_value(ctx.url, SAFE_SQL_PAYLOAD))
    ctx.sql_probe = sql_probe

    baseline_body = baseline.text if baseline else ""
    probe_body = sql_probe.text if sql_probe else ""
    response_length_delta = abs(len(probe_body) - len(baseline_body))

    baseline_status = baseline.status_code if baseline else 0
    probe_status = sql_probe.status_code if sql_probe else 0
    status_change = baseline_status != probe_status

    lower_probe = probe_body.lower()
    error_signatures = [token for token in SQL_ERROR_TOKENS if token in lower_probe]

    ctx.stages.append(
        {
            "stage": "Stage 5: Behavioral validation",
            "response_length_delta": response_length_delta,
            "status_code_comparison": {"baseline": baseline_status, "probe": probe_status, "changed": status_change},
            "error_signature_detection": error_signatures,
        }
    )


def _stage6_confidence_engine(ctx: StageContext) -> dict[str, Any]:
    stage2 = ctx.stages[1]
    stage3 = ctx.stages[2]
    stage4 = ctx.stages[3]
    stage5 = ctx.stages[4]

    mitigated = stage4["mitigation_count"] > 0

    reflection_score = 1.0 if stage2["parameter_reflection"] else 0.0
    context_multiplier = {"script_block": 1.0, "attribute": 0.8, "html": 0.65, "none": 0.0}.get(stage2["context_classification"], 0.0)
    encoding_penalty = 0.45 if (stage3["html_encoding_detected"] or stage3["javascript_escaping_detected"]) else 1.0
    behavior_bonus = 0.15 if stage5["response_length_delta"] > 30 else 0.0

    exploitability = round(10 * reflection_score * context_multiplier * encoding_penalty + (behavior_bonus * 10), 2)
    confidence = 40 + (35 if stage2["parameter_reflection"] else 0) + (15 if stage5["status_code_comparison"]["changed"] else 0)
    confidence += min(10, len(stage5["error_signature_detection"]) * 4)
    if mitigated:
        confidence -= 12

    sql_exploitability = 0.0
    if stage5["error_signature_detection"] or stage5["status_code_comparison"]["changed"]:
        sql_exploitability = 5.5 + min(3.0, len(stage5["error_signature_detection"]) * 0.7)

    missing_headers = [
        name
        for name, present in {
            "Content-Security-Policy": stage4["mitigations"]["csp"],
            "X-Frame-Options": stage4["mitigations"]["x_frame_options"],
            "Strict-Transport-Security": stage4["mitigations"]["hsts"],
        }.items()
        if not present
    ]

    findings = [
        _build_finding(
            vulnerability="Reflected Input / Potential XSS",
            exploitability_score=exploitability,
            confidence=confidence,
            mitigation_present=mitigated,
            explanation=(
                "Reflection was evaluated across HTML/script contexts with encoding checks. "
                "Mitigations (CSP/XFO/HSTS) are applied to reduce practical exploitability."
            ),
        ),
        _build_finding(
            vulnerability="SQL Error Leakage / Injection Indicator",
            exploitability_score=sql_exploitability,
            confidence=55 + min(30, len(stage5["error_signature_detection"]) * 8),
            mitigation_present=stage4["mitigations"]["hsts"],
            explanation=(
                "Behavioral differences and database-like error signatures were compared against baseline responses "
                "using non-destructive probes."
            ),
        ),
        _build_finding(
            vulnerability="Browser-side Mitigation Coverage",
            exploitability_score=4.5 if missing_headers else 0.5,
            confidence=82,
            mitigation_present=not bool(missing_headers),
            explanation=(
                "Security hardening header coverage was assessed. Missing headers increase clickjacking, script "
                "execution, and transport downgrade exposure."
            ),
        ),
    ]

    stage = {
        "stage": "Stage 6: Confidence engine",
        "false_positive_reduction": [
            "Cross-validated reflection with encoding detection",
            "Compared behavioral deltas against baseline",
            "Reduced confidence when mitigations are present",
        ],
        "findings_generated": findings,
    }
    ctx.stages.append(stage)
    return stage


def run_owasp_scan(url: str) -> dict[str, Any]:
    ctx = StageContext(url=url)
    _stage1_passive_recon(ctx)
    _stage2_reflection_detection(ctx)
    _stage3_encoding_validation(ctx)
    _stage4_mitigation_awareness(ctx)
    _stage5_behavioral_validation(ctx)
    stage6 = _stage6_confidence_engine(ctx)
    return {"stages": ctx.stages, "findings": stage6["findings_generated"]}
