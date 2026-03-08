from __future__ import annotations

from typing import Any

import requests


class BurpScanner:
    """Burp API/proxy integration with normalized finding output."""

    def __init__(self, api_url: str = "http://127.0.0.1:1337", timeout: int = 20) -> None:
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    def run(self, target_url: str) -> dict[str, Any]:
        """
        Expects a Burp-compatible endpoint exposing scan issues.
        Example response schema:
        {
          "issues": [{"name": "XSS", "severity": "high", "path": "/search", "confidence": "Firm", ...}]
        }
        """
        try:
            response = requests.post(
                f"{self.api_url}/v1/scan",
                json={"target": target_url},
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            findings = [self._normalize_issue(issue) for issue in payload.get("issues", [])]
            return {"scanner": "Burp Suite", "status": "ok", "findings": findings}
        except Exception as exc:  # noqa: BLE001
            return {"scanner": "Burp Suite", "status": "error", "error": str(exc), "findings": []}

    def _normalize_issue(self, issue: dict[str, Any]) -> dict[str, Any]:
        confidence_map = {"Tentative": 0.45, "Firm": 0.75, "Certain": 0.9}
        return {
            "vulnerability": issue.get("name", "Unknown finding"),
            "scanner": "Burp Suite",
            "endpoint": issue.get("path") or issue.get("url") or "",
            "severity": (issue.get("severity") or "info").title(),
            "confidence": confidence_map.get(issue.get("confidence", "Tentative"), 0.55),
            "description": issue.get("description", ""),
            "evidence": issue.get("evidence", ""),
            "cwe_id": issue.get("cwe"),
            "owasp_category": "Uncategorized",
            "raw": issue,
        }
