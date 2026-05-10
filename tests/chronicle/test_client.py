"""Chronicle client — UDM Search request shape + health probe + region URL map."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
import respx

from secops_term.chronicle import auth as auth_mod
from secops_term.chronicle import client as client_mod

# Fixtures


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _client(
    *, customer_id: str = "cust-123", region: str = "us", token: str = "t-1"
) -> client_mod.ChronicleClient:
    cfg = client_mod.ChronicleConfig(customer_id=customer_id, region=region)
    return client_mod.ChronicleClient(cfg, auth=auth_mod.StaticTokenAuth(token))


# Region URL


@pytest.mark.parametrize(
    ("region", "expected"),
    [
        ("us", "https://us-chronicle.googleapis.com"),
        ("europe", "https://europe-chronicle.googleapis.com"),
        ("asia-southeast1", "https://asia-southeast1-chronicle.googleapis.com"),
    ],
)
def test_region_to_url(region: str, expected: str) -> None:
    cfg = client_mod.ChronicleConfig(customer_id="c", region=region)
    assert cfg.resolved_base_url() == expected


def test_unknown_region_raises_unless_base_url_set() -> None:
    cfg = client_mod.ChronicleConfig(customer_id="c", region="atlantis")
    with pytest.raises(client_mod.ChronicleError):
        cfg.resolved_base_url()


def test_explicit_base_url_overrides_region() -> None:
    cfg = client_mod.ChronicleConfig(
        customer_id="c",
        region="atlantis",
        base_url="https://custom-chronicle.example.com",
    )
    assert cfg.resolved_base_url() == "https://custom-chronicle.example.com"


def test_base_url_strips_trailing_slash() -> None:
    cfg = client_mod.ChronicleConfig(
        customer_id="c",
        region="us",
        base_url="https://x/",
    )
    assert cfg.resolved_base_url() == "https://x"


def test_udm_search_url_has_customer_id() -> None:
    c = _client(customer_id="abc-123")
    assert c.udm_search_url() == ("https://us-chronicle.googleapis.com/v1alpha/abc-123:udmSearch")


# UDM Search request shape


async def test_udm_search_posts_json_with_bearer_token(
    respx_router: respx.Router,
) -> None:
    route = respx_router.post(
        "https://us-chronicle.googleapis.com/v1alpha/cust-123:udmSearch"
    ).mock(
        return_value=httpx.Response(
            200,
            json={"events": [], "total_events": 0, "more_data_available": False},
        )
    )
    c = _client(token="my-token")
    result = await c.udm_search('principal.ip = "8.8.8.8"', lookback_hours=24, limit=10)
    assert result.events == []
    assert result.total_events == 0
    request = route.calls[0].request
    assert request.headers.get("Authorization") == "Bearer my-token"
    body = json.loads(request.content)
    assert body["query"] == 'principal.ip = "8.8.8.8"'
    assert body["limit"] == 10
    assert "start_time" in body["time_range"]
    assert "end_time" in body["time_range"]


async def test_udm_search_returns_events(respx_router: respx.Router) -> None:
    sample_events = [
        {"metadata": {"event_type": "NETWORK_CONNECTION"}},
        {"metadata": {"event_type": "PROCESS_LAUNCH"}},
    ]
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-123:udmSearch").mock(
        return_value=httpx.Response(
            200,
            json={
                "events": sample_events,
                "total_events": 2,
                "more_data_available": False,
            },
        )
    )
    c = _client()
    result = await c.udm_search('target.file.sha256 = "a" * 64')
    assert len(result.events) == 2
    assert result.total_events == 2
    assert result.more_data_available is False
    assert result.events[0]["metadata"]["event_type"] == "NETWORK_CONNECTION"


async def test_udm_search_handles_missing_events_field(
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-123:udmSearch").mock(
        return_value=httpx.Response(200, json={})
    )
    c = _client()
    result = await c.udm_search('principal.ip = "1.1.1.1"')
    assert result.events == []
    assert result.total_events is None


async def test_udm_search_handles_more_data_flag(
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-123:udmSearch").mock(
        return_value=httpx.Response(
            200,
            json={
                "events": [{"x": 1}],
                "total_events": 1000,
                "more_data_available": True,
            },
        )
    )
    c = _client()
    result = await c.udm_search('principal.ip = "1.1.1.1"')
    assert result.more_data_available is True


async def test_udm_search_passes_explicit_end_time(
    respx_router: respx.Router,
) -> None:
    route = respx_router.post(
        "https://us-chronicle.googleapis.com/v1alpha/cust-123:udmSearch"
    ).mock(return_value=httpx.Response(200, json={"events": []}))
    c = _client()
    await c.udm_search(
        'principal.ip = "1.1.1.1"',
        lookback_hours=24,
        end_time=datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC),
    )
    body = json.loads(route.calls[0].request.content)
    assert body["time_range"]["end_time"].startswith("2026-06-01T12:00:00")
    assert body["time_range"]["start_time"].startswith("2026-05-31T12:00:00")


# UDM Search error paths


async def test_udm_search_rejects_empty_query() -> None:
    c = _client()
    with pytest.raises(client_mod.ChronicleError):
        await c.udm_search("")


async def test_udm_search_rejects_zero_limit() -> None:
    c = _client()
    with pytest.raises(client_mod.ChronicleError):
        await c.udm_search('principal.ip = "1.1.1.1"', limit=0)


async def test_udm_search_rejects_zero_lookback() -> None:
    c = _client()
    with pytest.raises(client_mod.ChronicleError):
        await c.udm_search('principal.ip = "1.1.1.1"', lookback_hours=0)


async def test_udm_search_raises_on_non_200(
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-123:udmSearch").mock(
        return_value=httpx.Response(500, text="internal-error-from-chronicle")
    )
    c = _client()
    with pytest.raises(client_mod.ChronicleAPIError) as exc_info:
        await c.udm_search('principal.ip = "1.1.1.1"')
    assert exc_info.value.status_code == 500


async def test_udm_search_raises_on_non_json(
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-123:udmSearch").mock(
        return_value=httpx.Response(200, text="<html>nope</html>")
    )
    c = _client()
    with pytest.raises(client_mod.ChronicleError):
        await c.udm_search('principal.ip = "1.1.1.1"')


# Health check


async def test_health_check_succeeds(respx_router: respx.Router) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-123:udmSearch").mock(
        return_value=httpx.Response(200, json={"events": []})
    )
    c = _client()
    status = await c.health_check()
    assert status.ok is True
    assert "us/cust-123" in status.detail


async def test_health_check_fails_on_401(respx_router: respx.Router) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-123:udmSearch").mock(
        return_value=httpx.Response(401, text="bad creds")
    )
    c = _client()
    status = await c.health_check()
    assert status.ok is False
    assert "401" in status.detail


async def test_health_check_fails_on_403(respx_router: respx.Router) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-123:udmSearch").mock(
        return_value=httpx.Response(403)
    )
    c = _client()
    status = await c.health_check()
    assert status.ok is False
    assert "403" in status.detail


async def test_health_check_fails_on_5xx(respx_router: respx.Router) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-123:udmSearch").mock(
        return_value=httpx.Response(503)
    )
    c = _client()
    status = await c.health_check()
    assert status.ok is False
    assert "503" in status.detail


async def test_health_check_fails_on_auth_error() -> None:
    """Auth provider raises → health probe surfaces as failure, not exception."""

    class _BoomAuth:
        async def get_token(self) -> str:
            raise auth_mod.ChronicleAuthError("simulated auth failure")

    cfg = client_mod.ChronicleConfig(customer_id="c", region="us")
    c = client_mod.ChronicleClient(cfg, auth=_BoomAuth())
    status = await c.health_check()
    assert status.ok is False
    assert "auth" in status.detail.lower()
