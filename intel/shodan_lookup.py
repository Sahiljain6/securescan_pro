from __future__ import annotations

import os
from typing import Any

import requests


class ShodanLookup:
    """Shodan host intelligence lookup."""

    def __init__(self, api_key: str | None = None, base_url: str = "https://api.shodan.io", timeout: int = 20) -> None:
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def lookup_host(self, host_or_ip: str) -> dict[str, Any]:
        if not self.api_key:
            return {"status": "skipped", "ports": [], "services": [], "vulns": []}

        try:
            response = requests.get(
                f"{self.base_url}/shodan/host/{host_or_ip}",
                params={"key": self.api_key},
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            return {
                "status": "ok",
                "organization": payload.get("org"),
                "ports": payload.get("ports", []),
                "services": sorted({entry.get("product", "unknown") for entry in payload.get("data", [])}),
                "vulns": payload.get("vulns", []),
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc), "ports": [], "services": [], "vulns": []}
