from __future__ import annotations

import os
from typing import Any

import requests


class NVDLookup:
    """NVD CVE enrichment helper for scanner findings."""

    def __init__(self, api_key: str | None = None, base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0", timeout: int = 20) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.base_url = base_url
        self.timeout = timeout

    def lookup(self, vulnerability: str, keyword_override: str | None = None) -> dict[str, Any]:
        keyword = keyword_override or vulnerability
        if not keyword:
            return {"status": "skipped", "cves": []}

        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            response = requests.get(
                self.base_url,
                params={"keywordSearch": keyword, "resultsPerPage": 3},
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            cves = [self._normalize_item(item) for item in payload.get("vulnerabilities", [])]
            return {"status": "ok", "cves": cves}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc), "cves": []}

    @staticmethod
    def _normalize_item(item: dict[str, Any]) -> dict[str, Any]:
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_entries = metrics.get(key, [])
            if metric_entries:
                cvss = metric_entries[0].get("cvssData", {})
                break

        descriptions = cve.get("descriptions", [])
        english = next((entry.get("value") for entry in descriptions if entry.get("lang") == "en"), "")

        return {
            "cve_id": cve.get("id"),
            "description": english,
            "cvss_base_score": cvss.get("baseScore") if cvss else None,
            "cvss_vector": cvss.get("vectorString") if cvss else None,
            "published": cve.get("published"),
        }
