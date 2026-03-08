from __future__ import annotations

from typing import Any

import requests


class SecurityHeadersLookup:
    """SecurityHeaders.com API client for header posture evaluation."""

    def __init__(self, api_key: str | None = None, base_url: str = "https://api.securityheaders.com", timeout: int = 20) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def evaluate(self, host: str) -> dict[str, Any]:
        headers = {"X-Api-Key": self.api_key} if self.api_key else {}
        try:
            response = requests.get(
                f"{self.base_url}/",
                params={"q": host, "followRedirects": "on", "hide": "on"},
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            grade = payload.get("grade", "N/A")
            return {
                "status": "ok",
                "grade": grade,
                "score": payload.get("score", 0),
                "missing_headers": payload.get("missing", []),
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc), "grade": "N/A", "score": 0, "missing_headers": []}
