from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

COMMON_PORTS = [80, 443, 21, 22, 25, 3306, 8080]


def scan_common_ports(target_url: str, timeout: float = 0.35) -> list[int]:
    hostname = _extract_host(target_url)
    if not hostname:
        return []

    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as executor:
        tasks = {executor.submit(_is_open, hostname, port, timeout): port for port in COMMON_PORTS}
        for future in as_completed(tasks):
            port = tasks[future]
            if future.result():
                open_ports.append(port)

    return sorted(open_ports)


def _extract_host(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return urlparse(target).hostname or ""
    return target


def _is_open(hostname: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((hostname, port)) == 0
    except OSError:
        return False
