from __future__ import annotations

import time
from typing import Any

import requests


SAFE_HTTP_RESULT: dict[str, Any] = {
    "status_code": 0,
    "response_headers": {},
    "redirects": [],
    "redirect_count": 0,
    "response_time": 0.0,
    "final_url": "",
    "error": None,
}


def scan_http(target_url: str, timeout: float = 2.5) -> dict[str, Any]:
    """Run a passive HTTP probe with strict timeout and safe fallback output."""
    started_at = time.perf_counter()
    try:
        response = requests.get(target_url, timeout=timeout, allow_redirects=True)
        redirects = [item.headers.get("Location", item.url) for item in response.history]
        return {
            "status_code": int(response.status_code),
            "response_headers": dict(response.headers),
            "redirects": redirects,
            "redirect_count": len(redirects),
            "response_time": round(time.perf_counter() - started_at, 4),
            "final_url": response.url,
            "error": None,
        }
    except requests.RequestException as exc:
        fallback = dict(SAFE_HTTP_RESULT)
        fallback["response_time"] = round(time.perf_counter() - started_at, 4)
        fallback["error"] = str(exc)
        return fallback
