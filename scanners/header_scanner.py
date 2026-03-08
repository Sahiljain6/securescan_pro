from __future__ import annotations

from typing import Any

REQUIRED_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def analyze_security_headers(response_headers: dict[str, Any] | None) -> dict[str, Any]:
    headers = {str(k).lower(): str(v) for k, v in (response_headers or {}).items()}
    missing_headers = [header for header in REQUIRED_SECURITY_HEADERS if header.lower() not in headers]
    present_count = len(REQUIRED_SECURITY_HEADERS) - len(missing_headers)
    header_score = round((present_count / len(REQUIRED_SECURITY_HEADERS)) * 10, 2)

    return {
        "missing_headers": missing_headers,
        "header_score": header_score,
    }
