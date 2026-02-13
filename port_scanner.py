import socket
from urllib.parse import urlparse

COMMON_PORTS = (21, 22, 23, 25, 53, 80, 443, 3306)


def _resolve_host(host: str) -> str:
    cleaned = (host or "").strip()
    if not cleaned:
        return ""
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        return parsed.hostname or ""
    return cleaned.split("/")[0]


def scan_ports(host):
    target = _resolve_host(host)
    if not target:
        return []

    open_ports = []
    for port in COMMON_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.7)
            if sock.connect_ex((target, port)) == 0:
                open_ports.append(port)

    return open_ports
