"""Vision One client — auth header, base URL, Search, Workbench, health probe."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
import respx

from secops_term.trendmicro import vision_one as v1


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _client(*, token: str = "test-token") -> v1.VisionOneClient:
    return v1.VisionOneClient(v1.VisionOneConfig(api_token=token))


# Config / construction


def test_config_locked_default_base_url() -> None:
    cfg = v1.VisionOneConfig(api_token="x")
    assert cfg.base_url == "https://api.xdr.trendmicro.com"
    assert cfg.resolved_base_url() == "https://api.xdr.trendmicro.com"


def test_config_strips_trailing_slash() -> None:
    cfg = v1.VisionOneConfig(api_token="x", base_url="https://x/")
    assert cfg.resolved_base_url() == "https://x"


def test_client_rejects_empty_token() -> None:
    with pytest.raises(v1.VisionOneError):
        v1.VisionOneClient(v1.VisionOneConfig(api_token=""))


def test_client_exposes_cfg_and_base_url() -> None:
    c = _client()
    assert c.cfg.api_token == "test-token"
    assert c.base_url == "https://api.xdr.trendmicro.com"


# Health check


async def test_health_check_succeeds(respx_router: respx.Router) -> None:
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/iam/account").mock(
        return_value=httpx.Response(200, json={"email": "soc@example.com", "loginAccount": "soc"})
    )
    status = await _client().health_check()
    assert status.ok is True
    assert "soc@example.com" in status.detail


async def test_health_check_succeeds_without_identity(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/iam/account").mock(
        return_value=httpx.Response(200, json={})
    )
    status = await _client().health_check()
    assert status.ok is True
    assert status.detail == "auth ok"


async def test_health_check_fails_on_401(respx_router: respx.Router) -> None:
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/iam/account").mock(
        return_value=httpx.Response(401)
    )
    status = await _client().health_check()
    assert status.ok is False
    assert "401" in status.detail


async def test_health_check_fails_on_403(respx_router: respx.Router) -> None:
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/iam/account").mock(
        return_value=httpx.Response(403)
    )
    status = await _client().health_check()
    assert status.ok is False
    assert "403" in status.detail


async def test_health_check_passes_bearer_token(
    respx_router: respx.Router,
) -> None:
    route = respx_router.get("https://api.xdr.trendmicro.com/v3.0/iam/account").mock(
        return_value=httpx.Response(200, json={})
    )
    await _client(token="abc-123").health_check()
    request = route.calls[0].request
    assert request.headers.get("Authorization") == "Bearer abc-123"


# Search activities


async def test_search_activities_returns_items(
    respx_router: respx.Router,
) -> None:
    items = [
        {"objectFileHashSha256": "a" * 64, "endpointHostName": "WIN-01"},
        {"objectFileHashSha256": "b" * 64, "endpointHostName": "WIN-02"},
    ]
    respx_router.post("https://api.xdr.trendmicro.com/v3.0/search/endpointActivities").mock(
        return_value=httpx.Response(200, json={"items": items, "nextLink": "https://x/page2"})
    )
    result = await _client().search_activities(
        'objectFileHashSha256:"a"', lookback_hours=24, limit=100
    )
    assert len(result.activities) == 2
    assert result.activities[0]["endpointHostName"] == "WIN-01"
    assert result.next_link == "https://x/page2"


async def test_search_activities_request_shape(
    respx_router: respx.Router,
) -> None:
    route = respx_router.post("https://api.xdr.trendmicro.com/v3.0/search/endpointActivities").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    await _client(token="my-token").search_activities(
        'objectFileHashSha256:"a"',
        lookback_hours=24,
        limit=50,
        end_time=datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC),
    )
    request = route.calls[0].request
    assert request.headers.get("Authorization") == "Bearer my-token"
    assert request.headers.get("Content-Type") == "application/json"
    body = json.loads(request.content)
    assert body == {"query": 'objectFileHashSha256:"a"'}
    url = str(request.url)
    assert "top=50" in url
    assert "startDateTime=2026-05-31T12" in url
    assert "endDateTime=2026-06-01T12" in url


async def test_search_activities_handles_missing_items(
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://api.xdr.trendmicro.com/v3.0/search/endpointActivities").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await _client().search_activities('objectFileHashSha256:"a"')
    assert result.activities == []
    assert result.next_link is None


async def test_search_activities_rejects_empty_query() -> None:
    with pytest.raises(v1.VisionOneError):
        await _client().search_activities("")


async def test_search_activities_rejects_zero_limit() -> None:
    with pytest.raises(v1.VisionOneError):
        await _client().search_activities('x:"y"', limit=0)


async def test_search_activities_rejects_huge_limit() -> None:
    with pytest.raises(v1.VisionOneError):
        await _client().search_activities('x:"y"', limit=10_000)


async def test_search_activities_rejects_zero_lookback() -> None:
    with pytest.raises(v1.VisionOneError):
        await _client().search_activities('x:"y"', lookback_hours=0)


async def test_search_activities_raises_on_5xx(
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://api.xdr.trendmicro.com/v3.0/search/endpointActivities").mock(
        return_value=httpx.Response(503)
    )
    with pytest.raises(v1.VisionOneAPIError) as exc_info:
        await _client().search_activities('x:"y"')
    assert exc_info.value.status_code == 503


async def test_search_activities_raises_on_non_json(
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://api.xdr.trendmicro.com/v3.0/search/endpointActivities").mock(
        return_value=httpx.Response(200, text="<html>nope</html>")
    )
    with pytest.raises(v1.VisionOneError):
        await _client().search_activities('x:"y"')


# Workbench alerts


async def test_workbench_alerts_returns_items(
    respx_router: respx.Router,
) -> None:
    alerts_payload = [
        {"id": "alert-1", "severity": "high", "model": "Suspicious PowerShell"},
        {"id": "alert-2", "severity": "medium", "model": "Login Anomaly"},
    ]
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(
            200,
            json={"items": alerts_payload, "totalCount": 2},
        )
    )
    result = await _client().list_workbench_alerts(limit=10)
    assert len(result.alerts) == 2
    assert result.total_count == 2
    assert result.alerts[0]["id"] == "alert-1"


async def test_workbench_alerts_filter_default(
    respx_router: respx.Router,
) -> None:
    """Default filter: investigationStatus = Open or InProgress."""
    route = respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    await _client().list_workbench_alerts()
    request = route.calls[0].request
    url = str(request.url)
    assert "investigationStatus" in url
    assert "Open" in url
    assert "InProgress" in url


async def test_workbench_alerts_custom_statuses(
    respx_router: respx.Router,
) -> None:
    route = respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    await _client().list_workbench_alerts(statuses=("Closed",))
    request = route.calls[0].request
    url = str(request.url)
    assert "Closed" in url
    assert "Open" not in url


async def test_workbench_alerts_with_since(
    respx_router: respx.Router,
) -> None:
    route = respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    await _client().list_workbench_alerts(since=datetime(2026, 1, 1, tzinfo=UTC))
    request = route.calls[0].request
    url = str(request.url)
    assert "startDateTime=2026-01-01T00" in url


async def test_workbench_alerts_passes_auth_header(
    respx_router: respx.Router,
) -> None:
    route = respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    await _client(token="alpha").list_workbench_alerts()
    request = route.calls[0].request
    assert request.headers.get("Authorization") == "Bearer alpha"


async def test_workbench_alerts_handles_missing_items(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await _client().list_workbench_alerts()
    assert result.alerts == []
    assert result.total_count is None


async def test_workbench_alerts_rejects_zero_limit() -> None:
    with pytest.raises(v1.VisionOneError):
        await _client().list_workbench_alerts(limit=0)


async def test_workbench_alerts_rejects_huge_limit() -> None:
    with pytest.raises(v1.VisionOneError):
        await _client().list_workbench_alerts(limit=10_000)


async def test_workbench_alerts_raises_on_500(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(500)
    )
    with pytest.raises(v1.VisionOneAPIError) as exc_info:
        await _client().list_workbench_alerts()
    assert exc_info.value.status_code == 500


async def test_workbench_alerts_raises_on_non_json(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(200, text="not-json")
    )
    with pytest.raises(v1.VisionOneError):
        await _client().list_workbench_alerts()
