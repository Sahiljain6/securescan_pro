from __future__ import annotations

from ml_model import model


def scan_url(url: str) -> tuple[str, float]:
    probability = model.predict_proba(url)
    if probability >= 0.75:
        verdict = "Malicious"
    elif probability >= 0.45:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
    return verdict, probability
