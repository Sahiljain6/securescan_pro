from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv3"}


def scan_tls(target_url: str, timeout: float = 2.0) -> dict[str, Any]:
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        return {
            "tls_status": "not_applicable",
            "issues": [],
            "tls_issues": 0,
            "tls_security_score": 5.0,
            "tls_version": "none",
            "certificate": {},
        }

    hostname = parsed.hostname or ""
    port = parsed.port or 443
    if not hostname:
        return _safe_tls_error("missing hostname")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_socket:
                cert = tls_socket.getpeercert()
                tls_version = tls_socket.version() or "unknown"

        issues: list[str] = []
        if _is_expired(cert):
            issues.append("expired_certificate")
        if _is_self_signed(cert):
            issues.append("self_signed_certificate")
        if tls_version in WEAK_TLS_VERSIONS:
            issues.append("weak_tls_version")

        tls_security_score = max(0.0, 10.0 - (len(issues) * 3.0))
        return {
            "tls_status": "secure" if not issues else "insecure",
            "issues": issues,
            "tls_issues": len(issues),
            "tls_security_score": round(tls_security_score, 2),
            "tls_version": tls_version,
            "certificate": {
                "subject": cert.get("subject", ()),
                "issuer": cert.get("issuer", ()),
                "notAfter": cert.get("notAfter", ""),
            },
        }
    except Exception as exc:  # noqa: BLE001
        return _safe_tls_error(str(exc))


def _is_expired(cert: dict[str, Any]) -> bool:
    not_after = cert.get("notAfter")
    if not not_after:
        return False
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return expiry < datetime.now(timezone.utc)
    except ValueError:
        return False


def _is_self_signed(cert: dict[str, Any]) -> bool:
    return cert.get("issuer") == cert.get("subject") and bool(cert.get("subject"))


def _safe_tls_error(error: str) -> dict[str, Any]:
    return {
        "tls_status": "unknown",
        "issues": ["tls_scan_failed"],
        "tls_issues": 1,
        "tls_security_score": 4.0,
        "tls_version": "unknown",
        "certificate": {},
        "error": error,
    }
