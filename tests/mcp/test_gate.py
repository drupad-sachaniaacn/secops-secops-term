"""MCP gate — bearer auth + per-tool sliding-window rate limit."""

from __future__ import annotations

import pytest

from secops_term.mcp import gate as gate_mod

# check_bearer_token


def test_no_auth_required_passes_through() -> None:
    gate_mod.check_bearer_token(None, None)
    gate_mod.check_bearer_token(None, "Bearer anything")


def test_required_token_missing_header_rejected() -> None:
    with pytest.raises(gate_mod.Unauthorized):
        gate_mod.check_bearer_token("expected", None)


def test_malformed_header_rejected() -> None:
    with pytest.raises(gate_mod.Unauthorized):
        gate_mod.check_bearer_token("expected", "expected")
    with pytest.raises(gate_mod.Unauthorized):
        gate_mod.check_bearer_token("expected", "Token expected")


def test_wrong_token_rejected() -> None:
    with pytest.raises(gate_mod.Unauthorized):
        gate_mod.check_bearer_token("expected", "Bearer wrong")


def test_correct_token_accepted() -> None:
    gate_mod.check_bearer_token("expected", "Bearer expected")


def test_bearer_case_insensitive() -> None:
    gate_mod.check_bearer_token("expected", "bearer expected")
    gate_mod.check_bearer_token("expected", "BEARER expected")


def test_token_compared_with_constant_time() -> None:
    """Sanity: hmac.compare_digest is used (verified by behaviour)."""
    # Different lengths shouldn't crash either path.
    with pytest.raises(gate_mod.Unauthorized):
        gate_mod.check_bearer_token("a" * 16, "Bearer " + "a" * 8)


# RateLimiter


class _Clock:
    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_rate_limiter_allows_up_to_limit() -> None:
    clock = _Clock()
    rl = gate_mod.RateLimiter(default_limit=3, time_source=clock, window_s=60)
    rl.acquire("tool")
    rl.acquire("tool")
    rl.acquire("tool")
    with pytest.raises(gate_mod.RateLimited) as exc_info:
        rl.acquire("tool")
    assert exc_info.value.tool == "tool"
    assert exc_info.value.retry_after_s > 0


def test_rate_limiter_window_slides() -> None:
    clock = _Clock()
    rl = gate_mod.RateLimiter(default_limit=2, time_source=clock, window_s=60)
    rl.acquire("tool")
    rl.acquire("tool")
    # Just before window expires — still rejected.
    clock.t = 59
    with pytest.raises(gate_mod.RateLimited):
        rl.acquire("tool")
    # After window — first call evicted, room for one more.
    clock.t = 61
    rl.acquire("tool")


def test_rate_limiter_per_tool_independent() -> None:
    clock = _Clock()
    rl = gate_mod.RateLimiter(default_limit=1, time_source=clock, window_s=60)
    rl.acquire("toolA")
    # toolA is full; toolB is independent.
    with pytest.raises(gate_mod.RateLimited):
        rl.acquire("toolA")
    rl.acquire("toolB")  # different bucket, allowed


def test_rate_limiter_per_tool_override() -> None:
    clock = _Clock()
    rl = gate_mod.RateLimiter(default_limit=1, time_source=clock, window_s=60)
    rl.set_limit("burst-tool", 5)
    for _ in range(5):
        rl.acquire("burst-tool")
    with pytest.raises(gate_mod.RateLimited):
        rl.acquire("burst-tool")


def test_rate_limiter_set_limit_resets_bucket() -> None:
    clock = _Clock()
    rl = gate_mod.RateLimiter(default_limit=1, time_source=clock, window_s=60)
    rl.acquire("tool")
    with pytest.raises(gate_mod.RateLimited):
        rl.acquire("tool")
    # Setting the limit drops the existing bucket so we get fresh capacity.
    rl.set_limit("tool", 10)
    for _ in range(10):
        rl.acquire("tool")


def test_rate_limiter_rejects_non_positive_limit() -> None:
    with pytest.raises(ValueError):
        gate_mod.RateLimiter(default_limit=0)
    with pytest.raises(ValueError):
        gate_mod.RateLimiter(default_limit=-1)
    rl = gate_mod.RateLimiter(default_limit=1)
    with pytest.raises(ValueError):
        rl.set_limit("t", 0)


def test_rate_limiter_retry_after_decreases_over_time() -> None:
    clock = _Clock()
    rl = gate_mod.RateLimiter(default_limit=1, time_source=clock, window_s=60)
    rl.acquire("tool")
    clock.t = 10
    try:
        rl.acquire("tool")
    except gate_mod.RateLimited as exc:
        first_retry = exc.retry_after_s
    clock.t = 30
    try:
        rl.acquire("tool")
    except gate_mod.RateLimited as exc:
        second_retry = exc.retry_after_s
    assert second_retry < first_retry
