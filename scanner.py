import ipaddress
import re
from urllib.parse import urlparse

from ml_model import get_model

SUSPICIOUS_KEYWORDS = {
    "login",
    "secure",
    "verify",
    "update",
    "account",
    "password",
    "bank",
    "confirm",
    "wallet",
    "signin",
}


def _ensure_scheme(url: str) -> str:
    cleaned = url.strip()
    if not cleaned:
        return cleaned
    if not cleaned.startswith(("http://", "https://")):
        return f"http://{cleaned}"
    return cleaned


def _contains_ip(hostname: str) -> int:
    if not hostname:
        return 0
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 1 if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname or "") else 0


def _extract_features(url: str) -> list[int]:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path_and_query = f"{parsed.path} {parsed.query}".lower()

    suspicious_hits = sum(1 for word in SUSPICIOUS_KEYWORDS if word in path_and_query)

    return [
        len(url),
        hostname.count("."),
        int("@" in url),
        _contains_ip(hostname),
        int(parsed.scheme == "https"),
        suspicious_hits,
    ]


def scan_url(url: str):
    normalized_url = _ensure_scheme(url)
    if not normalized_url:
        return "Suspicious", 0.55

    model = get_model()
    features = _extract_features(normalized_url)
    probabilities = model.predict_proba([features])[0]
    malicious_probability = float(probabilities[1])

    if malicious_probability >= 0.8:
        label = "Malicious"
    elif malicious_probability >= 0.45:
        label = "Suspicious"
    else:
        label = "Safe"

    return label, malicious_probability
