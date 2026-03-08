from __future__ import annotations

import os
from typing import Any
from urllib.parse import quote

import requests


class VirusTotalLookup:
    """VirusTotal domain and URL reputation checks."""

    def __init__(self, api_key: str | None = None, base_url: str = "https://www.virustotal.com/api/v3", timeout: int = 20) -> None:
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def domain_reputation(self, domain: str) -> dict[str, Any]:
        return self._lookup(f"/domains/{quote(domain, safe='')}")

    def url_reputation(self, url_id: str) -> dict[str, Any]:
        return self._lookup(f"/urls/{quote(url_id, safe='')}")

    def _lookup(self, path: str) -> dict[str, Any]:
        if not self.api_key:
            return {"status": "skipped", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
        try:
            response = requests.get(f"{self.base_url}{path}", headers={"x-apikey": self.api_key}, timeout=self.timeout)
            response.raise_for_status()
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "ok",
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "undetected": int(stats.get("undetected", 0)),
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc), "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
