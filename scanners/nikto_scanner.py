from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class NiktoScanner:
    """Nikto CLI wrapper that returns normalized findings."""

    def __init__(self, binary: str | None = None, timeout: int = 300) -> None:
        self.binary = binary or os.getenv("NIKTO_BINARY", "nikto")
        self.timeout = timeout

    def run(self, target_url: str) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "nikto_output.json"
            command = [
                self.binary,
                "-h",
                target_url,
                "-Format",
                "json",
                "-output",
                str(output_path),
                "-ask",
                "no",
            ]
            try:
                process = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout, check=False)
                if process.returncode not in {0, 1}:
                    raise RuntimeError(process.stderr.strip() or process.stdout.strip() or "Nikto execution failed")

                findings = self._parse_output(output_path) if output_path.exists() else []
                return {"scanner": "Nikto", "status": "ok", "findings": findings}
            except Exception as exc:  # noqa: BLE001
                return {"scanner": "Nikto", "status": "error", "error": str(exc), "findings": []}

    def _parse_output(self, json_file: Path) -> list[dict[str, Any]]:
        payload = json.loads(json_file.read_text(encoding="utf-8", errors="ignore") or "{}")
        vulnerabilities = payload.get("vulnerabilities", [])
        findings: list[dict[str, Any]] = []

        for item in vulnerabilities:
            findings.append(
                {
                    "vulnerability": item.get("msg", "Unknown finding"),
                    "endpoint": item.get("url") or item.get("uri") or "",
                    "severity": self._severity_from_message(item),
                    "scanner": "Nikto",
                    "confidence": 0.72,
                    "description": item.get("msg", ""),
                    "evidence": item.get("method", "GET"),
                    "cwe_id": item.get("cwe"),
                    "owasp_category": "Uncategorized",
                    "raw": item,
                }
            )

        return findings

    @staticmethod
    def _severity_from_message(item: dict[str, Any]) -> str:
        message = str(item.get("msg", "")).lower()
        if "injection" in message or "remote code" in message:
            return "High"
        if "xss" in message or item.get("osvdb"):
            return "Medium"
        return "Low"
