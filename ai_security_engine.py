from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any

import requests


OWASP_FALLBACK_MAP = {
    "injection": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "csrf": "A01:2021 - Broken Access Control",
    "security headers": "A05:2021 - Security Misconfiguration",
    "tls": "A02:2021 - Cryptographic Failures",
    "redirect": "A10:2021 - Server-Side Request Forgery",
    "open port": "A05:2021 - Security Misconfiguration",
    "http": "A05:2021 - Security Misconfiguration",
}


class AISecurityEngine:
    """OpenAI-assisted vulnerability analysis with deterministic fallback."""

    def __init__(self, api_key: str | None = None, model: str | None = None, timeout: int = 25) -> None:
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.timeout = timeout

    def analyze_vulnerability(self, vulnerability_list: list[dict[str, Any]]) -> dict[str, Any]:
        if not vulnerability_list:
            return {
                "vulnerabilities": [],
                "severity_distribution": {"Informational": 1},
                "owasp_categories": {"No OWASP Mapping": 1},
                "risk_score": 0,
                "ai_analysis": {
                    "engine": "fallback",
                    "summary": "No findings were supplied for AI analysis.",
                    "model": self.model,
                },
            }

        fallback = self._fallback_analysis(vulnerability_list)
        if not self.api_key:
            fallback["ai_analysis"]["reason"] = "OPENAI_API_KEY not configured"
            return fallback

        try:
            ai_payload = self._call_openai(vulnerability_list)
            normalized = self._normalize_ai_payload(vulnerability_list, ai_payload)
            return normalized
        except Exception as exc:  # noqa: BLE001
            fallback["ai_analysis"]["reason"] = f"OpenAI request failed: {exc}"
            return fallback

    def _call_openai(self, vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
        prompt = {
            "task": "Analyze vulnerabilities and return JSON only.",
            "required_fields": ["summary", "vulnerability_analysis"],
            "vulnerability_analysis_item_schema": {
                "vulnerability": "string",
                "classification": "string",
                "severity": "Informational|Low|Medium|High|Critical",
                "risk_score": "number 0-10",
                "owasp_category": "string",
                "mitigation": "string",
            },
            "input": vulnerabilities,
        }

        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={
                "model": self.model,
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a defensive cybersecurity analyst. Provide precise, concise security triage output in strict JSON.",
                    },
                    {"role": "user", "content": json.dumps(prompt)},
                ],
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return json.loads(content)

    def _normalize_ai_payload(self, vulnerabilities: list[dict[str, Any]], ai_payload: dict[str, Any]) -> dict[str, Any]:
        ai_items = ai_payload.get("vulnerability_analysis", [])
        by_name = {str(item.get("vulnerability", "")).lower(): item for item in ai_items}

        enriched: list[dict[str, Any]] = []
        for vuln in vulnerabilities:
            key = str(vuln.get("vulnerability", "")).lower()
            ai_item = by_name.get(key, {})
            sev = ai_item.get("severity") or vuln.get("severity") or "Low"
            score = float(ai_item.get("risk_score", vuln.get("risk", {}).get("cvss_score", 0)))
            enriched.append(
                {
                    **vuln,
                    "classification": ai_item.get("classification", "General Web Vulnerability"),
                    "severity": sev,
                    "risk_score": round(max(0, min(10, score)), 2),
                    "owasp_category": ai_item.get("owasp_category", vuln.get("owasp_category", "Uncategorized")),
                    "mitigation": ai_item.get("mitigation", self._default_mitigation(vuln.get("vulnerability", ""))),
                }
            )

        severity_distribution = dict(Counter(item.get("severity", "Low") for item in enriched))
        owasp_categories = dict(Counter(item.get("owasp_category", "Uncategorized") for item in enriched))
        risk_score = round(sum(item.get("risk_score", 0) for item in enriched) / max(len(enriched), 1), 2)
        return {
            "vulnerabilities": enriched,
            "severity_distribution": severity_distribution,
            "owasp_categories": owasp_categories,
            "risk_score": risk_score,
            "ai_analysis": {
                "engine": "openai",
                "summary": ai_payload.get("summary", "AI analysis completed."),
                "model": self.model,
            },
        }

    def _fallback_analysis(self, vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
        normalized = []
        for vuln in vulnerabilities:
            severity = vuln.get("ml", {}).get("severity") or vuln.get("severity") or "Low"
            cvss_score = float(vuln.get("risk", {}).get("cvss_score", 0))
            classification = self._classify(vuln.get("vulnerability", ""))
            owasp_category = vuln.get("owasp_category") or self._owasp_category(vuln.get("vulnerability", ""))
            normalized.append(
                {
                    **vuln,
                    "classification": classification,
                    "severity": severity,
                    "risk_score": round(max(0, min(10, cvss_score)), 2),
                    "owasp_category": owasp_category,
                    "mitigation": self._default_mitigation(vuln.get("vulnerability", "")),
                }
            )

        severity_distribution = dict(Counter(item["severity"] for item in normalized))
        owasp_categories = dict(Counter(item["owasp_category"] for item in normalized))
        risk_score = round(sum(item["risk_score"] for item in normalized) / max(len(normalized), 1), 2)
        return {
            "vulnerabilities": normalized,
            "severity_distribution": severity_distribution,
            "owasp_categories": owasp_categories,
            "risk_score": risk_score,
            "ai_analysis": {
                "engine": "fallback",
                "summary": "Deterministic AI fallback used due to unavailable API response.",
                "model": self.model,
            },
        }

    @staticmethod
    def _classify(vulnerability_name: str) -> str:
        name = vulnerability_name.lower()
        if "injection" in name:
            return "Injection Flaw"
        if "header" in name or "misconfig" in name:
            return "Security Misconfiguration"
        if "tls" in name or "cipher" in name:
            return "Cryptographic Weakness"
        if "redirect" in name:
            return "Redirect Abuse"
        return "General Web Vulnerability"

    def _owasp_category(self, vulnerability_name: str) -> str:
        lowered = vulnerability_name.lower()
        for signal, category in OWASP_FALLBACK_MAP.items():
            if signal in lowered:
                return category
        return "Uncategorized"

    @staticmethod
    def _default_mitigation(vulnerability_name: str) -> str:
        lowered = vulnerability_name.lower()
        if "header" in lowered:
            return "Add missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)."
        if "tls" in lowered:
            return "Disable legacy TLS/cipher suites and enforce TLS 1.2+ with modern cipher suites."
        if "redirect" in lowered:
            return "Allow-list redirect targets and reject untrusted redirect parameters."
        if "port" in lowered:
            return "Close unnecessary externally accessible ports and restrict access with firewall rules."
        return "Apply input validation, hardening, and monitoring controls for this vulnerability class."


def analyze_vulnerability(vulnerability_list: list[dict[str, Any]]) -> dict[str, Any]:
    return AISecurityEngine().analyze_vulnerability(vulnerability_list)
