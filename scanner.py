from __future__ import annotations

import socket
import ssl
from urllib.parse import urljoin

import requests

from ml_model import model
from port_scanner import scan_ports

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def scan_url(url: str) -> tuple[str, float]:
    probability = model.predict_proba(url)
    if probability >= 0.75:
        verdict = "Malicious"
    elif probability >= 0.45:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
    return verdict, probability


def run_defensive_web_checks(url: str, timeout: int = 12) -> dict:
    """Perform passive/defensive web checks with robust cloud-safe fallbacks."""
    findings: list[dict] = []

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        findings.extend(_check_security_headers(response))
        findings.extend(_check_http_misconfiguration(response))
        findings.extend(_check_suspicious_redirects(response))
    except requests.RequestException as exc:
        return {
            "scanner": "Defensive Web Checks",
            "status": "error",
            "error": str(exc),
            "findings": [],
        }

    findings.extend(_check_open_ports(url))
    findings.extend(_check_tls(url))
    return {"scanner": "Defensive Web Checks", "status": "ok", "findings": findings}


def _check_security_headers(response: requests.Response) -> list[dict]:
    findings = []
    for header in SECURITY_HEADERS:
        if header not in response.headers:
            findings.append(
                {
                    "vulnerability": f"Missing {header} Header",
                    "endpoint": response.url,
                    "severity": "Medium",
                    "scanner": "Defensive Web Checks",
                    "confidence": 0.78,
                    "description": f"{header} header is missing.",
                }
            )
    return findings


def _check_http_misconfiguration(response: requests.Response) -> list[dict]:
    findings = []
    server_header = response.headers.get("Server", "")
    if server_header and any(char.isdigit() for char in server_header):
        findings.append(
            {
                "vulnerability": "Server Version Disclosure",
                "endpoint": response.url,
                "severity": "Low",
                "scanner": "Defensive Web Checks",
                "confidence": 0.7,
                "description": f"Server header leaks implementation details: {server_header}",
            }
        )

    if response.status_code >= 500:
        findings.append(
            {
                "vulnerability": "HTTP Misconfiguration",
                "endpoint": response.url,
                "severity": "Medium",
                "scanner": "Defensive Web Checks",
                "confidence": 0.66,
                "description": f"Server returned {response.status_code} during passive probe.",
            }
        )
    return findings


def _check_suspicious_redirects(response: requests.Response) -> list[dict]:
    findings = []
    for item in response.history:
        location = item.headers.get("Location", "")
        if location.startswith("http") and not location.startswith(response.url.split("/")[0] + "//" + response.url.split("/")[2]):
            findings.append(
                {
                    "vulnerability": "Suspicious External Redirect",
                    "endpoint": item.url,
                    "severity": "Medium",
                    "scanner": "Defensive Web Checks",
                    "confidence": 0.69,
                    "description": f"Redirect chain includes external destination: {location}",
                }
            )
        elif location.startswith("/") and "//" in location.replace("//", "", 1):
            findings.append(
                {
                    "vulnerability": "Potential Open Redirect Pattern",
                    "endpoint": urljoin(item.url, location),
                    "severity": "Medium",
                    "scanner": "Defensive Web Checks",
                    "confidence": 0.64,
                    "description": "Location header contains ambiguous redirect pattern.",
                }
            )
    return findings


def _check_open_ports(url: str) -> list[dict]:
    risky_ports = {21, 22, 23, 25, 3306, 5432, 6379, 27017}
    findings = []
    for port in scan_ports(url):
        if port in risky_ports:
            findings.append(
                {
                    "vulnerability": f"Open Port {port}",
                    "endpoint": url,
                    "severity": "Medium",
                    "scanner": "Defensive Web Checks",
                    "confidence": 0.75,
                    "description": "Sensitive network service appears reachable from scanner vantage point.",
                }
            )
    return findings


def _check_tls(url: str) -> list[dict]:
    if not url.startswith("https://"):
        return []

    host = url.split("//", 1)[1].split("/", 1)[0]
    hostname = host.split(":")[0]
    port = int(host.split(":")[1]) if ":" in host else 443

    findings = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_socket:
                version = tls_socket.version() or "unknown"
                cipher = tls_socket.cipher()[0] if tls_socket.cipher() else ""
                if version in {"TLSv1", "TLSv1.1", "SSLv3"}:
                    findings.append(
                        {
                            "vulnerability": "Weak TLS Protocol",
                            "endpoint": url,
                            "severity": "High",
                            "scanner": "Defensive Web Checks",
                            "confidence": 0.82,
                            "description": f"Legacy TLS protocol negotiated: {version}",
                        }
                    )
                if "RC4" in cipher or "3DES" in cipher:
                    findings.append(
                        {
                            "vulnerability": "Weak TLS Cipher",
                            "endpoint": url,
                            "severity": "High",
                            "scanner": "Defensive Web Checks",
                            "confidence": 0.8,
                            "description": f"Weak cipher suite in use: {cipher}",
                        }
                    )
    except OSError:
        findings.append(
            {
                "vulnerability": "TLS Configuration Unverified",
                "endpoint": url,
                "severity": "Low",
                "scanner": "Defensive Web Checks",
                "confidence": 0.4,
                "description": "Could not establish TLS socket for passive verification.",
            }
        )
    return findings
