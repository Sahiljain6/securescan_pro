from __future__ import annotations


class MitigationAnalyzer:
    SECURITY_HEADERS = {
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
    }

    def analyze_headers(self, headers: dict[str, str]) -> dict[str, object]:
        present = sorted([header for header in self.SECURITY_HEADERS if headers.get(header)])
        coverage = len(present) / len(self.SECURITY_HEADERS)
        return {
            "present_controls": present,
            "missing_controls": sorted(self.SECURITY_HEADERS.difference(present)),
            "coverage": round(coverage, 3),
        }

    def analyze_session_controls(self, headers: dict[str, str]) -> dict[str, object]:
        cookie = headers.get("Set-Cookie", "").lower()
        session_controls = {
            "httponly": "httponly" in cookie,
            "secure": "secure" in cookie,
            "samesite": "samesite" in cookie,
        }
        strength = sum(session_controls.values()) / len(session_controls)
        return {"controls": session_controls, "strength": round(strength, 3)}
