from __future__ import annotations

import time
from typing import Any

import requests


class ZAPScanner:
    """OWASP ZAP REST API client with normalized finding output."""

    def __init__(self, base_url: str = "http://127.0.0.1:8080", api_key: str | None = None, timeout: int = 20) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or ""
        self.timeout = timeout

    def _params(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        params = {"apikey": self.api_key} if self.api_key else {}
        if extra:
            params.update(extra)
        return params

    def _get_json(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = requests.get(
            f"{self.base_url}{path}",
            params=self._params(params),
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def _wait_for_completion(self, status_path: str, status_key: str, scan_id: str, poll_seconds: float = 1.0) -> None:
        for _ in range(120):
            status_payload = self._get_json(status_path, {"scanId": scan_id})
            if int(status_payload.get(status_key, 0)) >= 100:
                return
            time.sleep(poll_seconds)

    def run(self, target_url: str) -> dict[str, Any]:
        try:
            spider = self._get_json("/JSON/spider/action/scan/", {"url": target_url, "maxChildren": 20})
            spider_id = spider.get("scan", "0")
            self._wait_for_completion("/JSON/spider/view/status/", "status", spider_id)

            active = self._get_json("/JSON/ascan/action/scan/", {"url": target_url, "recurse": "true"})
            active_id = active.get("scan", "0")
            self._wait_for_completion("/JSON/ascan/view/status/", "status", active_id)

            alerts_payload = self._get_json("/JSON/core/view/alerts/", {"baseurl": target_url})
            findings = [self._normalize_alert(alert) for alert in alerts_payload.get("alerts", [])]
            return {"scanner": "OWASP ZAP", "status": "ok", "findings": findings}
        except Exception as exc:  # noqa: BLE001
            return {"scanner": "OWASP ZAP", "status": "error", "error": str(exc), "findings": []}

    def _normalize_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        confidence_map = {"Low": 0.4, "Medium": 0.65, "High": 0.82, "Informational": 0.3}
        return {
            "vulnerability": (alert.get("alert") or "Unknown finding").strip(),
            "scanner": "OWASP ZAP",
            "endpoint": alert.get("url", ""),
            "severity": alert.get("risk", "Informational"),
            "confidence": confidence_map.get(alert.get("confidence", "Low"), 0.5),
            "description": alert.get("description", ""),
            "evidence": alert.get("evidence", ""),
            "cwe_id": alert.get("cweid"),
            "owasp_category": "Uncategorized",
            "raw": alert,
        }
