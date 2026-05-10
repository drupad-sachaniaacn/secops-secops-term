"""``HardenedClient``: timeouts, size cap, retry budget, audit emission."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from secops_term.core import audit
from secops_term.core import http as core_http


@pytest.fixture
def respx_router() -> respx.Router:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


# Basic happy path


async def test_get_basic_success(respx_router: respx.Router) -> None:
    respx_router.get("https://api.example.com/foo").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    async with core_http.HardenedClient() as client:
        r = await client.get("https://api.example.com/foo")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


async def test_post_success(respx_router: respx.Router) -> None:
    respx_router.post("https://api.example.com/foo").mock(
        return_value=httpx.Response(201, json={"id": 1})
    )
    async with core_http.HardenedClient() as client:
        r = await client.post("https://api.example.com/foo", json={"x": 1})
    assert r.status_code == 201


# Response size cap


async def test_response_too_large_via_content_length(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://api.example.com/big").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Length": str(10_000_000)},
            content=b"x" * 100,
        )
    )
    cfg = core_http.HTTPConfig(response_cap_bytes=1_000_000, max_retries=1)
    async with core_http.HardenedClient(cfg) as client:
        with pytest.raises(core_http.ResponseTooLarge):
            await client.get("https://api.example.com/big")


async def test_response_within_cap_succeeds(respx_router: respx.Router) -> None:
    respx_router.get("https://api.example.com/small").mock(
        return_value=httpx.Response(200, content=b"x" * 100)
    )
    cfg = core_http.HTTPConfig(response_cap_bytes=1_000_000)
    async with core_http.HardenedClient(cfg) as client:
        r = await client.get("https://api.example.com/small")
    assert r.status_code == 200
    assert len(r.content) == 100


async def test_per_call_cap_above_ceiling_raises() -> None:
    async with core_http.HardenedClient() as client:
        with pytest.raises(core_http.CapTooHigh):
            await client.request(
                "GET",
                "https://example.com/",
                response_cap_bytes=core_http.HARD_CEILING_BYTES + 1,
            )


def test_config_cap_above_ceiling_raises() -> None:
    cfg = core_http.HTTPConfig(response_cap_bytes=core_http.HARD_CEILING_BYTES + 1)
    with pytest.raises(core_http.CapTooHigh):
        core_http.HardenedClient(cfg)


# Retry policy


async def test_retry_on_503_then_succeed(respx_router: respx.Router) -> None:
    route = respx_router.get("https://api.example.com/flaky").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(503),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    cfg = core_http.HTTPConfig(max_retries=3)
    async with core_http.HardenedClient(cfg) as client:
        r = await client.get("https://api.example.com/flaky")
    assert r.status_code == 200
    assert route.call_count == 3


async def test_retry_budget_exhausted_returns_last_response(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://api.example.com/down").mock(return_value=httpx.Response(503))
    cfg = core_http.HTTPConfig(max_retries=2)
    async with core_http.HardenedClient(cfg) as client:
        r = await client.get("https://api.example.com/down")
    assert r.status_code == 503


async def test_4xx_not_retried(respx_router: respx.Router) -> None:
    route = respx_router.get("https://api.example.com/notfound").mock(
        return_value=httpx.Response(404)
    )
    cfg = core_http.HTTPConfig(max_retries=3)
    async with core_http.HardenedClient(cfg) as client:
        r = await client.get("https://api.example.com/notfound")
    assert r.status_code == 404
    assert route.call_count == 1


async def test_429_is_retried(respx_router: respx.Router) -> None:
    route = respx_router.get("https://api.example.com/limited").mock(
        side_effect=[
            httpx.Response(429),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    cfg = core_http.HTTPConfig(max_retries=3)
    async with core_http.HardenedClient(cfg) as client:
        r = await client.get("https://api.example.com/limited")
    assert r.status_code == 200
    assert route.call_count == 2


# Audit emission


async def test_audit_logs_each_call(respx_router: respx.Router, tmp_root: Path) -> None:
    log = audit.AuditLogger(path=tmp_root / "audit.jsonl")
    respx_router.get("https://api.example.com/foo").mock(return_value=httpx.Response(200))
    async with core_http.HardenedClient(audit_logger=log) as client:
        await client.get("https://api.example.com/foo")
    text = (tmp_root / "audit.jsonl").read_text(encoding="utf-8")
    assert '"kind":"http"' in text
    assert "api.example.com" in text


async def test_audit_logs_retry_attempts(respx_router: respx.Router, tmp_root: Path) -> None:
    log = audit.AuditLogger(path=tmp_root / "audit.jsonl")
    respx_router.get("https://api.example.com/flaky").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200),
        ]
    )
    cfg = core_http.HTTPConfig(max_retries=3)
    async with core_http.HardenedClient(cfg, audit_logger=log) as client:
        await client.get("https://api.example.com/flaky")
    text = (tmp_root / "audit.jsonl").read_text(encoding="utf-8")
    assert text.count('"kind":"http"') == 2
    assert '"attempt":1' in text
    assert '"attempt":2' in text


# Lifecycle


async def test_request_without_open_raises() -> None:
    client = core_http.HardenedClient()
    with pytest.raises(core_http.HTTPError):
        await client.get("https://example.com/")
