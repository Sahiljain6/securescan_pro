from __future__ import annotations

from typing import Any


def analyze_redirects(redirects: list[str] | None) -> dict[str, Any]:
    chain = [item for item in (redirects or []) if item]
    seen: set[str] = set()
    loop_detected = False
    for location in chain:
        if location in seen:
            loop_detected = True
            break
        seen.add(location)

    return {
        "redirect_count": len(chain),
        "multiple_redirects": len(chain) > 1,
        "redirect_loop": loop_detected,
    }
