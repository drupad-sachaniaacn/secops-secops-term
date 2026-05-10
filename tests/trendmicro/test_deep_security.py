"""Deep Security read-only client — auth header, list_agents, list_alerts, health."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
import respx

from secops_term.trendmicro import deep_security as ds


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _client(
    *,
    api_key: str = "ds-test-key",
    base_url: str = "https://app.deepsecurity.trendmicro.com",
    deployment_type: ds.DeploymentType = "dsaas",
) -> ds.DeepSecurityClient:
    return ds.DeepSecurityClient(
        ds.DeepSecurityConfig(
            api_key=api_key,
            base_url=base_url,
            deployment_type=deployment_type,
        )
    )


# Config / construction


def test_config_strips_trailing_slash() -> None:
    cfg = ds.DeepSecurityConfig(api_key="k", base_url="https://x/")
    assert cfg.resolved_base_url() == "https://x"


def test_client_rejects_empty_api_key() -> None:
    with pytest.raises(ds.DeepSecurityError):
        ds.DeepSecurityClient(ds.DeepSecurityConfig(api_key="", base_url="https://x"))


def test_client_rejects_empty_base_url() -> None:
    with pytest.raises(ds.DeepSecurityError):
        ds.DeepSecurityClient(ds.DeepSecurityConfig(api_key="k", base_url=""))


def test_client_rejects_unknown_deployment_type() -> None:
    with pytest.raises(ds.DeepSecurityError):
        ds.DeepSecurityClient(
            ds.DeepSecurityConfig(
                api_key="k",
                base_url="https://x",
                deployment_type="cloud-or-something",  # type: ignore[arg-type]
            )
        )


def test_client_exposes_cfg_and_base_url() -> None:
    c = _client()
    assert c.cfg.api_key == "ds-test-key"
    assert c.base_url == "https://app.deepsecurity.trendmicro.com"


def test_no_allow_write_field() -> None:
    """DS scope is locked read-only — there is no `allow_write` knob."""
    cfg = ds.DeepSecurityConfig(api_key="k", base_url="https://x")
    assert not hasattr(cfg, "allow_write")


# Health probe


async def test_health_check_succeeds_dsaas(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/computers").mock(
        return_value=httpx.Response(200, json={"computers": []})
    )
    status = await _client().health_check()
    assert status.ok is True
    assert "dsaas" in status.detail


async def test_health_check_succeeds_on_prem(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://dsm.example.com/api/computers").mock(
        return_value=httpx.Response(200, json={"computers": []})
    )
    status = await _client(
        base_url="https://dsm.example.com", deployment_type="on_prem"
    ).health_check()
    assert status.ok is True
    assert "on_prem" in status.detail


async def test_health_check_fails_on_401(respx_router: respx.Router) -> None:
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/computers").mock(
        return_value=httpx.Response(401)
    )
    status = await _client().health_check()
    assert status.ok is False
    assert "401" in status.detail


async def test_health_check_fails_on_403(respx_router: respx.Router) -> None:
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/computers").mock(
        return_value=httpx.Response(403)
    )
    status = await _client().health_check()
    assert status.ok is False
    assert "403" in status.detail


async def test_health_check_fails_on_500(respx_router: respx.Router) -> None:
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/computers").mock(
        return_value=httpx.Response(500)
    )
    status = await _client().health_check()
    assert status.ok is False
    assert "500" in status.detail


async def test_health_check_passes_required_headers(
    respx_router: respx.Router,
) -> None:
    route = respx_router.get("https://app.deepsecurity.trendmicro.com/api/computers").mock(
        return_value=httpx.Response(200, json={"computers": []})
    )
    await _client(api_key="my-key").health_check()
    request = route.calls[0].request
    assert request.headers.get("api-secret-key") == "my-key"
    assert request.headers.get("api-version") == "v1"


async def test_health_check_uses_limit_one(
    respx_router: respx.Router,
) -> None:
    route = respx_router.get("https://app.deepsecurity.trendmicro.com/api/computers").mock(
        return_value=httpx.Response(200, json={"computers": []})
    )
    await _client().health_check()
    assert "limit=1" in str(route.calls[0].request.url)


# list_agents


async def test_list_agents_returns_items(respx_router: respx.Router) -> None:
    payload = {
        "computers": [
            {
                "ID": 1,
                "displayName": "WIN-01",
                "computerStatus": {"agentStatus": "active"},
            },
            {
                "ID": 2,
                "displayName": "LIN-02",
                "computerStatus": {"agentStatus": "offline"},
            },
        ],
        "total": 2,
    }
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/computers").mock(
        return_value=httpx.Response(200, json=payload)
    )
    result = await _client().list_agents(limit=50)
    assert len(result.agents) == 2
    assert result.agents[0]["displayName"] == "WIN-01"
    assert result.total == 2


async def test_list_agents_passes_auth(respx_router: respx.Router) -> None:
    route = respx_router.get("https://app.deepsecurity.trendmicro.com/api/computers").mock(
        return_value=httpx.Response(200, json={"computers": []})
    )
    await _client(api_key="some-key").list_agents()
    request = route.calls[0].request
    assert request.headers.get("api-secret-key") == "some-key"


async def test_list_agents_handles_missing_field(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/computers").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await _client().list_agents()
    assert result.agents == []
    assert result.total is None


async def test_list_agents_rejects_zero_limit() -> None:
    with pytest.raises(ds.DeepSecurityError):
        await _client().list_agents(limit=0)


async def test_list_agents_rejects_huge_limit() -> None:
    with pytest.raises(ds.DeepSecurityError):
        await _client().list_agents(limit=10_000)


async def test_list_agents_raises_on_5xx(respx_router: respx.Router) -> None:
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/computers").mock(
        return_value=httpx.Response(503)
    )
    with pytest.raises(ds.DeepSecurityAPIError) as exc_info:
        await _client().list_agents()
    assert exc_info.value.status_code == 503


async def test_list_agents_raises_on_non_json(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/computers").mock(
        return_value=httpx.Response(200, text="<html>nope</html>")
    )
    with pytest.raises(ds.DeepSecurityError):
        await _client().list_agents()


# list_alerts


async def test_list_alerts_returns_items(respx_router: respx.Router) -> None:
    payload = {
        "alerts": [
            {"ID": 100, "name": "Anti-Malware Alert", "severity": "high"},
            {"ID": 101, "name": "Firewall Alert", "severity": "medium"},
        ],
        "totalCount": 2,
    }
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/alerts").mock(
        return_value=httpx.Response(200, json=payload)
    )
    result = await _client().list_alerts()
    assert len(result.alerts) == 2
    assert result.alerts[0]["severity"] == "high"
    assert result.total == 2


async def test_list_alerts_passes_since_param(
    respx_router: respx.Router,
) -> None:
    route = respx_router.get("https://app.deepsecurity.trendmicro.com/api/alerts").mock(
        return_value=httpx.Response(200, json={"alerts": []})
    )
    await _client().list_alerts(since=datetime(2026, 1, 1, tzinfo=UTC))
    url = str(route.calls[0].request.url)
    assert "since=2026-01-01T00" in url


async def test_list_alerts_no_since_omits_param(
    respx_router: respx.Router,
) -> None:
    route = respx_router.get("https://app.deepsecurity.trendmicro.com/api/alerts").mock(
        return_value=httpx.Response(200, json={"alerts": []})
    )
    await _client().list_alerts()
    url = str(route.calls[0].request.url)
    assert "since" not in url


async def test_list_alerts_passes_auth(respx_router: respx.Router) -> None:
    route = respx_router.get("https://app.deepsecurity.trendmicro.com/api/alerts").mock(
        return_value=httpx.Response(200, json={"alerts": []})
    )
    await _client(api_key="alpha").list_alerts()
    assert route.calls[0].request.headers.get("api-secret-key") == "alpha"


async def test_list_alerts_handles_missing_field(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/alerts").mock(
        return_value=httpx.Response(200, json={})
    )
    result = await _client().list_alerts()
    assert result.alerts == []


async def test_list_alerts_rejects_zero_limit() -> None:
    with pytest.raises(ds.DeepSecurityError):
        await _client().list_alerts(limit=0)


async def test_list_alerts_rejects_huge_limit() -> None:
    with pytest.raises(ds.DeepSecurityError):
        await _client().list_alerts(limit=10_000)


async def test_list_alerts_raises_on_5xx(respx_router: respx.Router) -> None:
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/alerts").mock(
        return_value=httpx.Response(500)
    )
    with pytest.raises(ds.DeepSecurityAPIError) as exc_info:
        await _client().list_alerts()
    assert exc_info.value.status_code == 500


async def test_list_alerts_raises_on_non_json(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/alerts").mock(
        return_value=httpx.Response(200, text="not-json")
    )
    with pytest.raises(ds.DeepSecurityError):
        await _client().list_alerts()
