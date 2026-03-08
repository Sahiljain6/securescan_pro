from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass
class URLFeatures:
    length: int
    has_ip: int
    num_dots: int
    has_at: int
    has_https: int
    suspicious_words: int


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "banking",
    "password",
    "confirm",
    "token",
}


class LightweightPhishingModel:
    """Hybrid lightweight model for URL phishing + scanner feature risk classification."""

    def _extract(self, url: str) -> URLFeatures:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        path = parsed.path.lower()
        full = f"{hostname}{path}"

        has_ip = int(bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", hostname)))
        has_at = int("@" in url)
        suspicious_words = sum(1 for word in SUSPICIOUS_KEYWORDS if word in full)

        return URLFeatures(
            length=len(url),
            has_ip=has_ip,
            num_dots=hostname.count("."),
            has_at=has_at,
            has_https=int(parsed.scheme == "https"),
            suspicious_words=suspicious_words,
        )

    def predict_proba(self, url: str) -> float:
        f = self._extract(url)
        raw_score = (
            0.015 * f.length
            + 1.6 * f.has_ip
            + 0.45 * f.num_dots
            + 1.0 * f.has_at
            - 1.2 * f.has_https
            + 0.8 * f.suspicious_words
            - 3.0
        )
        probability = 1 / (1 + math.exp(-raw_score))
        return max(0.01, min(0.99, probability))

    def classify_scanner_risk(self, scanner_findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Scanner results -> feature extraction -> AI risk classification inputs -> final aggregate score."""
        if not scanner_findings:
            return {"feature_vector": [0, 0, 0, 0], "risk_band": "Informational", "score": 0.0}

        severity_weights = {"Informational": 0.1, "Low": 0.3, "Medium": 0.6, "High": 0.8, "Critical": 1.0}
        finding_count = len(scanner_findings)
        avg_confidence = sum(float(item.get("confidence", 0.5)) for item in scanner_findings) / finding_count
        avg_severity = sum(severity_weights.get(item.get("severity", "Low"), 0.3) for item in scanner_findings) / finding_count
        scanner_diversity = len({item.get("scanner", "Unknown") for item in scanner_findings}) / 4

        composite = max(0.0, min(1.0, (0.45 * avg_severity) + (0.35 * avg_confidence) + (0.20 * scanner_diversity)))
        if composite >= 0.85:
            band = "Critical"
        elif composite >= 0.7:
            band = "High"
        elif composite >= 0.45:
            band = "Medium"
        elif composite >= 0.2:
            band = "Low"
        else:
            band = "Informational"

        return {
            "feature_vector": [round(avg_severity, 3), round(avg_confidence, 3), round(scanner_diversity, 3), finding_count],
            "risk_band": band,
            "score": round(composite * 10, 2),
        }


model = LightweightPhishingModel()
