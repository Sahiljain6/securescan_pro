from __future__ import annotations

import re
import socket
import ssl
from html import unescape
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

SAFE_TEST_PARAM = "sspro_test"
SAFE_XSS_PAYLOAD = "<script>SecureScanPro_reflection_check</script>"
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
]
SQL_ERROR_TOKENS = ["sql syntax", "mysql", "sqlite", "postgresql", "odbc", "database error", "sqlstate"]


def _request(url: str, params: dict | None = None) -> tuple[int, str, dict] | None:
    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if params:
            for key, value in params.items():
                query[key] = [value]

        final_query = urlencode({k: v[-1] for k, v in query.items()})
        final_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, final_query, parsed.fragment))

        req = Request(final_url, headers={"User-Agent": "SecureScanPro/2.0", "Accept": "text/html,*/*"})
        with urlopen(req, timeout=7) as response:  # noqa: S310
            body = response.read().decode("utf-8", errors="ignore")
            return response.status, body, dict(response.headers.items())
    except Exception:  # noqa: BLE001
        return None


def detect_sql_injection(url: str) -> dict:
    baseline = _request(url, {SAFE_TEST_PARAM: "1"})
    quote_probe = _request(url, {SAFE_TEST_PARAM: "1'"})
    logic_probe = _request(url, {SAFE_TEST_PARAM: "1 OR 1=1"})

    evidence: list[str] = []
    for probe in [quote_probe, logic_probe]:
        if probe:
            lower_body = probe[1].lower()
            evidence.extend([t for t in SQL_ERROR_TOKENS if t in lower_body])

    status_drift = bool(baseline and logic_probe and baseline[0] != logic_probe[0])
    vulnerable = bool(evidence or status_drift)

    return {
        "name": "SQL Injection (Passive)",
        "vulnerable": vulnerable,
        "confidence": "Medium" if vulnerable else "Informational",
        "details": "Potential SQL injection indicators from error leakage/status drift." if vulnerable else "No SQLi error leakage detected.",
        "evidence": sorted(set(evidence + (["http_status_changed"] if status_drift else []))),
    }


def detect_xss(url: str) -> dict:
    probe = _request(url, {SAFE_TEST_PARAM: SAFE_XSS_PAYLOAD})
    if not probe:
        return {
            "name": "Reflected XSS (Passive Reflection)",
            "vulnerable": False,
            "confidence": "Informational",
            "details": "Unable to inspect reflected payload behavior.",
            "evidence": [],
        }

    _, body, headers = probe
    csp_header = headers.get("Content-Security-Policy", "")
    csp_strict = bool(csp_header and "unsafe-inline" not in csp_header.lower())

    raw_reflection = SAFE_XSS_PAYLOAD in body
    encoded_payload = SAFE_XSS_PAYLOAD.replace("<", "&lt;").replace(">", "&gt;")
    html_encoded_reflection = encoded_payload in body
    param_reflection_only = "SecureScanPro_reflection_check" in unescape(body)

    confidence = "Informational"
    details = "No reflected payload behavior identified."
    evidence: list[str] = []

    if raw_reflection:
        confidence = "High"
        details = "Raw script payload reflected in response body (high-confidence reflected XSS indicator)."
        evidence.append("raw_reflection")
    elif html_encoded_reflection:
        confidence = "Low"
        details = "Payload reflected in HTML-encoded form; reflection exists but direct execution is less likely."
        evidence.append("html_encoded_reflection")
    elif param_reflection_only:
        confidence = "Low"
        details = "Parameter reflection observed with no direct script execution signature."
        evidence.append("param_reflection_no_execution")

    if csp_strict and confidence in {"High", "Medium"}:
        confidence = "Medium"
        evidence.append("csp_mitigates_inline_script")
        details += " Strict CSP present, reducing practical exploitability confidence."

    vulnerable = confidence in {"High", "Medium", "Low"}
    return {
        "name": "Reflected XSS (Passive Reflection)",
        "vulnerable": vulnerable,
        "confidence": confidence,
        "details": details,
        "evidence": evidence,
        "csp_present": bool(csp_header),
    }


def detect_csrf(url: str) -> dict:
    page = _request(url)
    if not page:
        return {
            "name": "CSRF Protections",
            "vulnerable": False,
            "confidence": "Informational",
            "details": "Unable to retrieve page.",
            "evidence": [],
        }

    body = page[1]
    forms = re.findall(r"<form[^>]*method=['\"]?post['\"]?[^>]*>(.*?)</form>", body, flags=re.IGNORECASE | re.DOTALL)
    missing_tokens = 0
    for form in forms:
        if not re.search(r"name=['\"][^'\"]*csrf[^'\"]*['\"]", form, flags=re.IGNORECASE):
            missing_tokens += 1

    vulnerable = missing_tokens > 0
    return {
        "name": "CSRF Protections",
        "vulnerable": vulnerable,
        "confidence": "Medium" if vulnerable else "Low",
        "details": f"{missing_tokens} POST form(s) without visible CSRF token fields." if vulnerable else "POST forms include token-like CSRF indicators.",
        "evidence": [f"missing_tokens={missing_tokens}"] if vulnerable else [],
    }


def check_security_headers(url: str) -> dict:
    page = _request(url)
    headers = page[2] if page else {}
    missing = [header for header in SECURITY_HEADERS if header not in headers]
    return {
        "name": "Security Headers",
        "vulnerable": bool(missing),
        "confidence": "Medium" if missing else "Low",
        "details": "Missing recommended response security headers." if missing else "Core security headers are present.",
        "evidence": missing,
        "csp_present": "Content-Security-Policy" in headers,
    }


def check_ssl_cert(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {
            "name": "TLS/SSL Certificate",
            "vulnerable": True,
            "confidence": "High",
            "details": "Target is not HTTPS.",
            "evidence": ["non_https"],
        }

    host = parsed.hostname
    if not host:
        return {
            "name": "TLS/SSL Certificate",
            "vulnerable": True,
            "confidence": "High",
            "details": "Invalid hostname.",
            "evidence": ["invalid_host"],
        }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()
        return {
            "name": "TLS/SSL Certificate",
            "vulnerable": False,
            "confidence": "Low",
            "details": f"Certificate validated (notAfter={cert.get('notAfter', 'unknown')}).",
            "evidence": [],
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "name": "TLS/SSL Certificate",
            "vulnerable": True,
            "confidence": "High",
            "details": "Unable to validate TLS certificate.",
            "evidence": [str(exc)],
        }


def run_owasp_scan(url: str) -> list[dict]:
    return [
        detect_sql_injection(url),
        detect_xss(url),
        detect_csrf(url),
        check_security_headers(url),
        check_ssl_cert(url),
    ]
