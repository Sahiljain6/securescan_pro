from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class NiktoScanner:
    """Nikto CLI wrapper that returns normalized findings."""

    def __init__(self, binary: str = "nikto", timeout: int = 300) -> None:
        self.binary = binary
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
                if process.returncode not in {0, 1}:  # 1 can represent findings discovered.
                    raise RuntimeError(process.stderr.strip() or process.stdout.strip() or "Nikto execution failed")
                if not output_path.exists():
                    return {"scanner": "Nikto", "status": "ok", "findings": []}
                findings = self._parse_output(output_path)
                return {"scanner": "Nikto", "status": "ok", "findings": findings}
            except Exception as exc:  # noqa: BLE001
                return {"scanner": "Nikto", "status": "error", "error": str(exc), "findings": []}

    def _parse_output(self, json_file: Path) -> list[dict[str, Any]]:
        payload = json.loads(json_file.read_text(encoding="utf-8", errors="ignore") or "{}")
        items = payload.get("vulnerabilities", [])
        findings: list[dict[str, Any]] = []
        for item in items:
            findings.append(
                {
                    "vulnerability": item.get("msg", "Unknown finding"),
                    "scanner": "Nikto",
                    "endpoint": item.get("url") or item.get("uri") or "",
                    "severity": self._severity_from_osvdb(item),
                    "confidence": 0.7,
                    "description": item.get("msg", ""),
                    "evidence": item.get("method", "GET"),
                    "cwe_id": item.get("cwe"),
                    "owasp_category": "Uncategorized",
                    "raw": item,
                }
            )
        return findings

    @staticmethod
    def _severity_from_osvdb(item: dict[str, Any]) -> str:
        if item.get("osvdb"):
            return "Medium"
        return "Low"
