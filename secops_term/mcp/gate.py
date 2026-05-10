"""MCP gate — bearer-token auth + per-tool rate limiting.

Decoupled from the wire-protocol layer so the policy can be tested
without spinning up a real server. The server module composes
:func:`check_bearer_token` + :class:`RateLimiter` around each tool
invocation.
"""

from __future__ import annotations

import hmac
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

DEFAULT_PER_TOOL_RATE = 60  # calls per minute (brief §3.5.9)
RATE_WINDOW_S = 60.0


class GateError(Exception):
    """Base for gate-level rejections."""


class Unauthorized(GateError):
    """Bearer-token check failed."""


class RateLimited(GateError):
    """Per-tool rate limit exceeded; retry after ``retry_after_s`` seconds."""

    def __init__(self, tool: str, retry_after_s: float) -> None:
        super().__init__(f"rate limit for tool {tool!r} exceeded; retry after {retry_after_s:.1f}s")
        self.tool = tool
        self.retry_after_s = retry_after_s


def check_bearer_token(expected: str | None, supplied_authorization_header: str | None) -> None:
    """Validate ``Authorization: Bearer <token>`` against the expected token.

    - ``expected is None`` → auth disabled, anything is accepted.
    - ``expected`` set, header missing or malformed → :class:`Unauthorized`.
    - Token mismatch → :class:`Unauthorized`. Comparison uses
      :func:`hmac.compare_digest` to defeat timing oracles.

    Per brief §3.5.9: when a shared-secret is configured the server
    rejects unauthenticated requests with 401.
    """
    if expected is None:
        return  # auth disabled
    if not supplied_authorization_header:
        raise Unauthorized("missing Authorization header")
    parts = supplied_authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise Unauthorized("expected `Authorization: Bearer <token>`")
    presented = parts[1].strip()
    if not hmac.compare_digest(presented, expected):
        raise Unauthorized("bearer token mismatch")


@dataclass
class _Bucket:
    """Rolling-window bucket for one tool."""

    limit: int
    timestamps: deque[float] = field(default_factory=deque)


class RateLimiter:
    """Per-tool sliding-window rate limiter (default 60 calls/min).

    Custom limits can be set per tool name via :meth:`set_limit`. Calls
    use a monotonic clock so wall-clock skew can't bypass the window.
    The ``time_source`` hook lets tests inject a deterministic clock.
    """

    def __init__(
        self,
        *,
        default_limit: int = DEFAULT_PER_TOOL_RATE,
        per_tool: Mapping[str, int] | None = None,
        time_source: Callable[[], float] | None = None,
        window_s: float = RATE_WINDOW_S,
    ) -> None:
        if default_limit <= 0:
            raise ValueError("default_limit must be positive")
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        self._default = default_limit
        self._overrides: dict[str, int] = dict(per_tool) if per_tool else {}
        self._buckets: dict[str, _Bucket] = {}
        self._now = time_source if time_source is not None else time.monotonic
        self._window = window_s

    def set_limit(self, tool: str, limit: int) -> None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        self._overrides[tool] = limit
        # Drop the existing bucket so the new limit applies immediately.
        self._buckets.pop(tool, None)

    def acquire(self, tool: str) -> None:
        """Record a call against ``tool``; raise :class:`RateLimited` if over.

        Uses a sliding window: each call appends a timestamp; on every
        call we evict timestamps older than ``_window`` seconds, then
        check whether the remaining count is under the limit.
        """
        limit = self._overrides.get(tool, self._default)
        bucket = self._buckets.setdefault(tool, _Bucket(limit=limit))
        now = self._now()
        cutoff = now - self._window
        while bucket.timestamps and bucket.timestamps[0] < cutoff:
            bucket.timestamps.popleft()
        if len(bucket.timestamps) >= limit:
            oldest = bucket.timestamps[0]
            retry_after = max(0.0, (oldest + self._window) - now)
            raise RateLimited(tool, retry_after)
        bucket.timestamps.append(now)


__all__ = [
    "DEFAULT_PER_TOOL_RATE",
    "GateError",
    "RateLimited",
    "RateLimiter",
    "Unauthorized",
    "check_bearer_token",
]
