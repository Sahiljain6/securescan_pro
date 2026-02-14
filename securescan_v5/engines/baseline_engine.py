from __future__ import annotations

import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, build_opener

from securescan_v5.models import HttpObservation

USER_AGENT = "SecureScanPro/5.0 (Defensive-Only, Behavioral Validation)"


class BaselineEngine:
    def fetch(self, url: str, stage: str = "baseline_capture") -> HttpObservation | None:
        req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"})
        started = time.perf_counter()
        try:
            with build_opener().open(req, timeout=8) as response:  # noqa: S310
                body = response.read().decode("utf-8", errors="ignore")
                elapsed = (time.perf_counter() - started) * 1000
                return HttpObservation(
                    stage=stage,
                    status_code=response.getcode(),
                    body=body,
                    headers=dict(response.headers.items()),
                    url=response.geturl(),
                    duration_ms=round(elapsed, 2),
                )
        except HTTPError as exc:
            elapsed = (time.perf_counter() - started) * 1000
            body = exc.read().decode("utf-8", errors="ignore") if exc.fp else ""
            return HttpObservation(
                stage=stage,
                status_code=exc.code,
                body=body,
                headers=dict(exc.headers.items()) if exc.headers else {},
                url=url,
                duration_ms=round(elapsed, 2),
            )
        except (URLError, TimeoutError, OSError):
            return None

    @staticmethod
    def inject_query(url: str, key: str, value: str) -> str:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        params[key] = value
        query = urlencode(params)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
