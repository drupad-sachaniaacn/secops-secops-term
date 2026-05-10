"""Health-check protocol and concurrent test runner.

Per brief v3 §3.5.14: every provider client (Chronicle, V1, DS, every intel
provider, every notifier) implements ``health_check()`` returning a
:class:`HealthStatus`. The CLI exposes ``secops-term config test <provider>``
and ``config test-all``; ``doctor`` calls the latter.

Probes must use the cheapest auth-validating endpoint (per provider). The
runner here is provider-agnostic: it just calls ``health_check()`` with a
timeout and aggregates results.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar, Protocol


@dataclass(frozen=True)
class HealthStatus:
    """Result of a single provider's health probe."""

    ok: bool
    latency_ms: float
    detail: str
    last_checked: datetime
    quota: dict[str, Any] | None = None


class HealthCheckable(Protocol):
    """Protocol every provider/notifier must implement.

    ``name`` is declared :class:`ClassVar` so concrete classes that set it
    at the class level (the brief's pattern — ``name: ClassVar[str] = "otx"``)
    satisfy the Protocol cleanly under ``mypy --strict``.
    """

    name: ClassVar[str]

    async def health_check(self) -> HealthStatus: ...


@dataclass(frozen=True)
class HealthRow:
    """One row in the ``test-all`` output table."""

    name: str
    instance: str | None
    status: HealthStatus
    error: str | None = None


def _failed(detail: str, *, latency_ms: float = 0.0) -> HealthStatus:
    return HealthStatus(
        ok=False,
        latency_ms=latency_ms,
        detail=detail,
        last_checked=datetime.now(UTC),
    )


class ProbeRateLimiter:
    """Per-(name, instance) probe-cadence limiter.

    Prevents a flapping CI loop from burning provider quotas on health checks.
    The runner does not auto-wire this — callers (CLI, doctor) decide whether
    to enforce. Thread-safe.
    """

    def __init__(self, min_interval_s: float = 30.0) -> None:
        self._min_interval = min_interval_s
        self._last: dict[tuple[str, str | None], float] = {}
        self._lock = threading.Lock()

    def can_probe(self, name: str, instance: str | None) -> bool:
        now = time.monotonic()
        key = (name, instance)
        with self._lock:
            return now - self._last.get(key, 0.0) >= self._min_interval

    def record(self, name: str, instance: str | None) -> None:
        key = (name, instance)
        with self._lock:
            self._last[key] = time.monotonic()


async def run_one(
    target: HealthCheckable,
    *,
    timeout_s: float = 10.0,
    instance: str | None = None,
) -> HealthRow:
    """Run a single health check with a timeout. Never raises."""
    started = time.monotonic()
    try:
        status = await asyncio.wait_for(target.health_check(), timeout=timeout_s)
        return HealthRow(name=target.name, instance=instance, status=status)
    except TimeoutError:
        latency_ms = (time.monotonic() - started) * 1000
        return HealthRow(
            name=target.name,
            instance=instance,
            status=_failed(f"timed out after {timeout_s}s", latency_ms=latency_ms),
            error="timeout",
        )
    except Exception as exc:
        latency_ms = (time.monotonic() - started) * 1000
        return HealthRow(
            name=target.name,
            instance=instance,
            status=_failed(f"{type(exc).__name__}: {exc}", latency_ms=latency_ms),
            error=str(exc),
        )


async def run_all(
    targets: Iterable[tuple[HealthCheckable, str | None]],
    *,
    timeout_s: float = 10.0,
    concurrency: int = 8,
) -> list[HealthRow]:
    """Run health checks concurrently. Returns rows in input order."""
    targets_list = list(targets)
    if not targets_list:
        return []
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(target: HealthCheckable, instance: str | None) -> HealthRow:
        async with semaphore:
            return await run_one(target, timeout_s=timeout_s, instance=instance)

    results = await asyncio.gather(*(_bounded(t, inst) for t, inst in targets_list))
    return list(results)
