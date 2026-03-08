from __future__ import annotations

import os
from typing import Any

import requests


class BurpScanner:
    """Burp Suite Enterprise/adapter API integration with normalized finding output."""

    def __init__(self, api_url: str | None = None, api_key: str | None = None, timeout: int = 20) -> None:
        self.api_url = (api_url or os.getenv("BURP_API_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("BURP_API_KEY", "")
        self.timeout = timeout

    def run(self, target_url: str) -> dict[str, Any]:
        if not self.api_url:
            return {"scanner": "Burp Suite", "status": "skipped", "error": "BURP_API_URL not configured", "findings": []}
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            response = requests.post(f"{self.api_url}/v1/scan", json={"target": target_url}, headers=headers, timeout=self.timeout)
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
            "endpoint": issue.get("path") or issue.get("url") or "",
            "severity": (issue.get("severity") or "info").title(),
            "scanner": "Burp Suite",
            "confidence": confidence_map.get(issue.get("confidence", "Tentative"), 0.55),
            "description": issue.get("description", ""),
            "evidence": issue.get("evidence", ""),
            "cwe_id": issue.get("cwe"),
            "owasp_category": "Uncategorized",
            "raw": issue,
        }
