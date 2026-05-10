"""Health-check protocol + concurrent runner."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from secops_term.core import health


class _OkProvider:
    name = "ok-provider"

    async def health_check(self) -> health.HealthStatus:
        return health.HealthStatus(
            ok=True,
            latency_ms=10.0,
            detail="ok",
            last_checked=datetime.now(UTC),
        )


class _FailProvider:
    name = "fail-provider"

    async def health_check(self) -> health.HealthStatus:
        raise RuntimeError("simulated failure")


class _SlowProvider:
    name = "slow-provider"

    async def health_check(self) -> health.HealthStatus:
        await asyncio.sleep(5)  # exceeds the 0.1s timeout in the test
        return health.HealthStatus(
            ok=True,
            latency_ms=5000.0,
            detail="ok",
            last_checked=datetime.now(UTC),
        )


# run_one


async def test_run_one_success() -> None:
    row = await health.run_one(_OkProvider())
    assert row.status.ok is True
    assert row.status.detail == "ok"
    assert row.error is None


async def test_run_one_exception_is_captured() -> None:
    row = await health.run_one(_FailProvider())
    assert row.status.ok is False
    assert "simulated failure" in row.status.detail
    assert row.error == "simulated failure"


async def test_run_one_timeout() -> None:
    row = await health.run_one(_SlowProvider(), timeout_s=0.1)
    assert row.status.ok is False
    assert "timed out" in row.status.detail
    assert row.error == "timeout"


async def test_run_one_passes_instance_label() -> None:
    row = await health.run_one(_OkProvider(), instance="primary")
    assert row.instance == "primary"


# run_all


async def test_run_all_returns_rows_in_input_order() -> None:
    targets = [
        (_OkProvider(), None),
        (_FailProvider(), None),
        (_OkProvider(), "instance-2"),
    ]
    rows = await health.run_all(targets)
    assert len(rows) == 3
    assert rows[0].status.ok is True
    assert rows[1].status.ok is False
    assert rows[2].instance == "instance-2"


async def test_run_all_empty() -> None:
    rows = await health.run_all([])
    assert rows == []


async def test_run_all_concurrency_bound() -> None:
    # 5 fast probes with concurrency=2; just verify all succeed.
    targets: list[tuple[health.HealthCheckable, str | None]] = [
        (_OkProvider(), str(i)) for i in range(5)
    ]
    rows = await health.run_all(targets, concurrency=2)
    assert len(rows) == 5
    assert all(r.status.ok for r in rows)


# ProbeRateLimiter


def test_rate_limiter_first_probe_allowed() -> None:
    limiter = health.ProbeRateLimiter(min_interval_s=30.0)
    assert limiter.can_probe("vt", "default") is True


def test_rate_limiter_blocks_within_window() -> None:
    limiter = health.ProbeRateLimiter(min_interval_s=30.0)
    limiter.record("vt", "default")
    assert limiter.can_probe("vt", "default") is False


def test_rate_limiter_per_instance_independent() -> None:
    limiter = health.ProbeRateLimiter(min_interval_s=30.0)
    limiter.record("vt", "default")
    assert limiter.can_probe("vt", "secondary") is True


def test_rate_limiter_zero_interval_always_allows() -> None:
    limiter = health.ProbeRateLimiter(min_interval_s=0.0)
    limiter.record("vt", "default")
    assert limiter.can_probe("vt", "default") is True
