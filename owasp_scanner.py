from __future__ import annotations

from typing import Any

from securescan_v5 import SecureScanV5


def run_owasp_scan(url: str) -> dict[str, Any]:
    scanner = SecureScanV5()
    return scanner.run(url)
