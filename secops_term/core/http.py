"""Shared, hardened ``httpx.AsyncClient`` with non-overridable defaults.

Per brief v3 §3.5.3:

- ``verify=True`` always. No ``--insecure`` flag exists.
- Timeouts: connect=10s, read=30s, write=10s, pool=5s.
- ``max_redirects=5``.
- Response size cap: 5 MB API, 50 MB feeds (per-call override possible,
  hard ceiling 200 MB).
- Scheme allowlist enforced upstream by :mod:`secops_term.core.url_guard`.
  This client trusts the caller to validate URLs first.
- HTTP/2 where the server supports it.
- Per-request retry budget: 3 attempts (configurable), exponential backoff
  with jitter, only on 408/429/500/502/503/504 and connection errors.
- Every call emits one audit log entry on completion (success or failure).
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets as _secrets
import time
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any

import httpx

from secops_term.core import audit

_DEFAULT_TIMEOUTS = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)
_DEFAULT_MAX_REDIRECTS = 5
_DEFAULT_RESPONSE_CAP_BYTES = 5 * 1024 * 1024
FEED_RESPONSE_CAP_BYTES = 50 * 1024 * 1024
HARD_CEILING_BYTES = 200 * 1024 * 1024

_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})


class HTTPError(Exception):
    """Base class for hardened-client errors."""


class ResponseTooLarge(HTTPError):
    """Response body exceeded the configured size cap."""


class RetryBudgetExhausted(HTTPError):
    """All retry attempts failed with a transport error."""


class CapTooHigh(HTTPError):
    """Caller passed a response cap above the hard ceiling."""


@dataclass(frozen=True)
class HTTPConfig:
    """Tunable parameters; all defaults match brief §3.5.3."""

    timeouts: httpx.Timeout = field(default_factory=lambda: _DEFAULT_TIMEOUTS)
    max_redirects: int = _DEFAULT_MAX_REDIRECTS
    response_cap_bytes: int = _DEFAULT_RESPONSE_CAP_BYTES
    max_retries: int = 3
    user_agent: str = "secops-term/0.1"


class HardenedClient:
    """``httpx.AsyncClient`` wrapper with the brief's hardened defaults.

    Use as an async context manager::

        async with HardenedClient() as http:
            r = await http.get("https://api.example.com/v1/foo")

    Schemes are validated by the caller via :mod:`secops_term.core.url_guard`
    *before* reaching this client. The client enforces TLS verify, timeouts,
    redirect cap, body-size cap, retry policy, and audit emission.
    """

    def __init__(
        self,
        cfg: HTTPConfig | None = None,
        *,
        audit_logger: audit.AuditLogger | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._cfg = cfg if cfg is not None else HTTPConfig()
        if self._cfg.response_cap_bytes > HARD_CEILING_BYTES:
            raise CapTooHigh(
                f"response_cap_bytes={self._cfg.response_cap_bytes} > "
                f"hard ceiling {HARD_CEILING_BYTES}"
            )
        self._audit = audit_logger
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HardenedClient:
        kwargs: dict[str, Any] = {
            "timeout": self._cfg.timeouts,
            "max_redirects": self._cfg.max_redirects,
            "verify": True,
            "http2": True,
            "follow_redirects": True,
            "headers": {"User-Agent": self._cfg.user_agent},
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        self._client = httpx.AsyncClient(**kwargs)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        method: str,
        url: str,
        *,
        response_cap_bytes: int | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Issue a request with retries, timeouts, and a body-size cap."""
        if self._client is None:
            raise HTTPError("HardenedClient not opened; use 'async with'")
        cap = response_cap_bytes if response_cap_bytes is not None else self._cfg.response_cap_bytes
        if cap > HARD_CEILING_BYTES:
            raise CapTooHigh(f"response_cap_bytes={cap} > hard ceiling {HARD_CEILING_BYTES}")

        last_response: httpx.Response | None = None
        last_exc: Exception | None = None
        for attempt in range(1, self._cfg.max_retries + 1):
            started = time.monotonic()
            try:
                response = await self._do_one(method, url, cap, **kwargs)
            except httpx.HTTPError as exc:
                latency_ms = (time.monotonic() - started) * 1000
                self._audit_call(
                    method,
                    url,
                    status=None,
                    latency_ms=latency_ms,
                    attempt=attempt,
                    error=str(exc),
                )
                last_exc = exc
                if attempt >= self._cfg.max_retries:
                    raise RetryBudgetExhausted(f"after {attempt} attempts: {exc}") from exc
                await self._backoff_sleep(attempt)
                continue

            latency_ms = (time.monotonic() - started) * 1000
            self._audit_call(
                method,
                url,
                status=response.status_code,
                latency_ms=latency_ms,
                attempt=attempt,
            )
            last_response = response
            if response.status_code in _RETRYABLE_STATUS and attempt < self._cfg.max_retries:
                await self._backoff_sleep(attempt)
                continue
            return response

        if last_response is not None:
            return last_response
        raise RetryBudgetExhausted(f"max_retries exhausted: {last_exc}")

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def _do_one(self, method: str, url: str, cap: int, **kwargs: Any) -> httpx.Response:
        if self._client is None:
            raise HTTPError("HardenedClient not opened; use 'async with'")
        async with self._client.stream(method, url, **kwargs) as resp:
            cl = resp.headers.get("Content-Length")
            if cl is not None:
                try:
                    cl_int = int(cl)
                except ValueError as exc:
                    raise HTTPError(f"invalid Content-Length: {cl!r}") from exc
                if cl_int > cap:
                    raise ResponseTooLarge(f"Content-Length {cl_int} > cap {cap}")
            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > cap:
                    raise ResponseTooLarge(f"streamed {total} bytes > cap {cap}")
                chunks.append(chunk)
            content = b"".join(chunks)
            return httpx.Response(
                status_code=resp.status_code,
                headers=resp.headers,
                content=content,
                request=resp.request,
                extensions=dict(resp.extensions),
            )

    async def _backoff_sleep(self, attempt: int) -> None:
        # Exponential backoff: 0.2, 0.4, 0.8, ... seconds, plus 0-25% jitter.
        # Crypto-strength randomness for jitter is overkill but cheap.
        base = 0.2 * (2 ** (attempt - 1))
        jitter_max = base * 0.25
        # randbelow gives [0, n); scale to [0, jitter_max].
        jitter = (_secrets.randbelow(1_000_000) / 1_000_000.0) * jitter_max
        await asyncio.sleep(base + jitter)

    def _audit_call(
        self,
        method: str,
        url: str,
        *,
        status: int | None,
        latency_ms: float,
        attempt: int,
        error: str | None = None,
    ) -> None:
        if self._audit is None:
            return
        entry: dict[str, Any] = {
            "kind": "http",
            "method": method,
            "url": url,
            "status": status,
            "latency_ms": round(latency_ms, 3),
            "attempt": attempt,
        }
        if error is not None:
            entry["error"] = error
        # Audit must never break the request path.
        with contextlib.suppress(Exception):
            self._audit.emit(entry)
