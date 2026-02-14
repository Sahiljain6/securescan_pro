from __future__ import annotations

import re
import socket
import ssl
from html import unescape
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

SAFE_TEST_PARAM = "sspro_test"
SAFE_XSS_PAYLOAD = "SecureScanPro_reflection_check"
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
]


def _request(url: str, params: dict | None = None) -> tuple[int, str, dict] | None:
    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if params:
            for key, value in params.items():
                query[key] = [value]
        full_query = urlencode({k: v[-1] for k, v in query.items()})
        final_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, full_query, parsed.fragment))
        req = Request(final_url, headers={"User-Agent": "SecureScanPro/2.0"})
        with urlopen(req, timeout=6) as resp:  # noqa: S310
            body = resp.read().decode("utf-8", errors="ignore")
            headers = dict(resp.headers.items())
            return resp.status, body, headers
    except Exception:  # noqa: BLE001
        return None


def detect_sql_injection(url: str) -> dict:
    baseline = _request(url, {SAFE_TEST_PARAM: "1"})
    probe = _request(url, {SAFE_TEST_PARAM: "1 OR 1=1"})

    indicators = []
    if probe:
        lower = probe[1].lower()
        for token in ["sql syntax", "mysql", "sqlite", "postgresql", "odbc", "database error"]:
            if token in lower:
                indicators.append(token)

    status_drift = bool(baseline and probe and baseline[0] != probe[0])
    vulnerable = bool(indicators or status_drift)
    return {
        "name": "SQL Injection (Passive)",
        "vulnerable": vulnerable,
        "details": "Potential SQL error leakage detected." if vulnerable else "No SQL error leakage detected.",
        "evidence": indicators,
    }


def detect_xss(url: str) -> dict:
    probe = _request(url, {SAFE_TEST_PARAM: SAFE_XSS_PAYLOAD})
    reflected = bool(probe and SAFE_XSS_PAYLOAD in unescape(probe[1]))
    return {
        "name": "Reflected XSS (Passive Reflection)",
        "vulnerable": reflected,
        "details": "Input reflected in response body; output encoding should be verified." if reflected else "No reflection observed.",
        "evidence": [SAFE_XSS_PAYLOAD] if reflected else [],
    }


def detect_csrf(url: str) -> dict:
    page = _request(url)
    if not page:
        return {"name": "CSRF Protections", "vulnerable": False, "details": "Unable to retrieve page.", "evidence": []}

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
        "details": f"{missing_tokens} POST form(s) without visible CSRF token fields." if vulnerable else "CSRF token indicators found for POST forms.",
        "evidence": [f"missing_tokens={missing_tokens}"] if vulnerable else [],
    }


def check_security_headers(url: str) -> dict:
    page = _request(url)
    headers = page[2] if page else {}
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    return {
        "name": "Security Headers",
        "vulnerable": bool(missing),
        "details": "Missing recommended security headers." if missing else "Core security headers are present.",
        "evidence": missing,
    }


def check_ssl_certificate(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"name": "TLS/SSL Certificate", "vulnerable": True, "details": "Target is not HTTPS.", "evidence": ["non_https"]}

    host = parsed.hostname
    if not host:
        return {"name": "TLS/SSL Certificate", "vulnerable": True, "details": "Invalid host.", "evidence": ["invalid_host"]}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()
        return {
            "name": "TLS/SSL Certificate",
            "vulnerable": False,
            "details": f"Certificate retrieved successfully (valid_to={cert.get('notAfter', 'unknown')}).",
            "evidence": [],
        }
    except Exception as exc:  # noqa: BLE001
        return {"name": "TLS/SSL Certificate", "vulnerable": True, "details": "Unable to validate TLS certificate.", "evidence": [str(exc)]}


def run_owasp_scan(url: str) -> list[dict]:
    return [
        detect_sql_injection(url),
        detect_xss(url),
        detect_csrf(url),
        check_security_headers(url),
        check_ssl_certificate(url),
    ]
