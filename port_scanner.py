from __future__ import annotations

import socket
from urllib.parse import urlparse

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 8080, 8443]


def _extract_host(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return urlparse(target).hostname or ""
    return target


def scan_ports(target: str, ports: list[int] | None = None, timeout: float = 0.35) -> list[int]:
    host = _extract_host(target)
    if not host:
        return []

    open_ports: list[int] = []
    for port in (ports or COMMON_PORTS):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
    return open_ports
