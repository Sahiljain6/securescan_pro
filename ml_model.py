from __future__ import annotations

import math
import re
from dataclasses import dataclass
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
    """A simple deterministic scoring model suitable for demo/lab environments."""

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


model = LightweightPhishingModel()
