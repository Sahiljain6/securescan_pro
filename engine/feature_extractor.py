from __future__ import annotations

from typing import Any


def extract_features(scan_result: dict[str, Any]) -> dict[str, Any]:
    header_score = float(scan_result.get("header_score", 0.0))
    open_ports = len(scan_result.get("open_ports", []))
    redirect_count = int(scan_result.get("redirects", 0))
    tls_security_score = float(scan_result.get("tls_security_score", 0.0))
    response_time = float(scan_result.get("response_time", 0.0))

    return {
        "feature_vector": [header_score, open_ports, redirect_count, tls_security_score, response_time],
        "header_score": header_score,
        "open_ports_count": open_ports,
        "redirect_count": redirect_count,
        "tls_security_score": tls_security_score,
        "response_time": response_time,
    }
