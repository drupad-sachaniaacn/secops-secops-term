"""AbuseIPDB provider — blacklist pull + /api/v2/check health probe."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from types import ModuleType

import httpx
import pytest
import respx

from secops_term.core import secrets as secrets_mod
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers import abuseipdb as aip_mod
from secops_term.intel.providers.base import IntelProviderError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _make_fake_keyring(token: str | None = "test-aip-key") -> ModuleType:
    class _FakeBackend:
        pass

    backend = _FakeBackend()
    store: dict[tuple[str, str], str] = {}
    if token is not None:
        store[("secops-term:intel.abuseipdb:default", "api_key")] = token

    def get_keyring() -> _FakeBackend:
        return backend

    def set_password(service: str, key: str, value: str) -> None:
        store[(service, key)] = value

    def get_password(service: str, key: str) -> str | None:
        return store.get((service, key))

    def delete_password(service: str, key: str) -> None:
        store.pop((service, key), None)

    mod = ModuleType("fake_keyring")
    mod.get_keyring = get_keyring  # type: ignore[attr-defined]
    mod.set_password = set_password  # type: ignore[attr-defined]
    mod.get_password = get_password  # type: ignore[attr-defined]
    mod.delete_password = delete_password  # type: ignore[attr-defined]
    return mod


@pytest.fixture
def fake_secrets_with_token() -> Iterator[None]:
    secrets_mod.reset_manager_for_tests()
    cfg = secrets_mod.SecretsConfig(keyring_module=_make_fake_keyring())
    secrets_mod.get_manager(cfg)
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


@pytest.fixture
def fake_secrets_no_token() -> Iterator[None]:
    secrets_mod.reset_manager_for_tests()
    cfg = secrets_mod.SecretsConfig(keyring_module=_make_fake_keyring(token=None))
    secrets_mod.get_manager(cfg)
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"
_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


def _ip_entry(
    ip: str = "1.2.3.4",
    score: int = 90,
    isp: str = "Bad ISP",
    usage: str = "Data Center/Web Hosting/Transit",
    last_reported: str = "2026-01-10T12:00:00+00:00",
) -> dict:
    return {
        "ipAddress": ip,
        "abuseConfidenceScore": score,
        "countryCode": "US",
        "isp": isp,
        "usageType": usage,
        "lastReportedAt": last_reported,
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registered() -> None:
    assert "abuseipdb" in PROVIDERS
    assert PROVIDERS.get("abuseipdb") is aip_mod.AbuseIPDBProvider


# ---------------------------------------------------------------------------
# from_config
# ---------------------------------------------------------------------------


def test_from_config_defaults() -> None:
    p = aip_mod.AbuseIPDBProvider.from_config("default", {})
    assert p.instance == "default"
    assert p._confidence == aip_mod._DEFAULT_CONFIDENCE
    assert p._limit == aip_mod._DEFAULT_LIMIT


def test_from_config_custom() -> None:
    p = aip_mod.AbuseIPDBProvider.from_config("prod", {"confidence_minimum": 90, "limit": 500})
    assert p._confidence == 90
    assert p._limit == 500


def test_from_config_clamps_confidence() -> None:
    p = aip_mod.AbuseIPDBProvider.from_config("default", {"confidence_minimum": 5})
    assert p._confidence == aip_mod._MIN_CONFIDENCE  # clamped up to 25


def test_from_config_clamps_limit() -> None:
    p = aip_mod.AbuseIPDBProvider.from_config("default", {"limit": 99999})
    assert p._limit == aip_mod._MAX_LIMIT  # capped at 10000


# ---------------------------------------------------------------------------
# pull()
# ---------------------------------------------------------------------------


async def test_pull_without_token_raises(fake_secrets_no_token: None) -> None:
    p = aip_mod.AbuseIPDBProvider("default")
    with pytest.raises(IntelProviderError):
        await p.pull()


async def test_pull_maps_ips(respx_router: respx.Router, fake_secrets_with_token: None) -> None:
    respx_router.get(_BLACKLIST_URL).mock(
        return_value=httpx.Response(
            200,
            json={"data": [_ip_entry("1.2.3.4", score=95), _ip_entry("5.6.7.8", score=80)]},
        )
    )
    p = aip_mod.AbuseIPDBProvider("default")
    records = await p.pull()
    assert len(records) == 2
    assert all(r.type == "ipv4" for r in records)
    assert {r.value for r in records} == {"1.2.3.4", "5.6.7.8"}
    assert all(r.source == "abuseipdb:default" for r in records)
    # Confidence score is preserved.
    assert any(r.confidence == 95 for r in records)


async def test_pull_sends_key_header(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    route = respx_router.get(_BLACKLIST_URL).mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    p = aip_mod.AbuseIPDBProvider("default")
    await p.pull()
    assert route.calls[0].request.headers.get("Key") == "test-aip-key"


async def test_pull_sends_confidence_param(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    route = respx_router.get(_BLACKLIST_URL).mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    p = aip_mod.AbuseIPDBProvider("default", confidence_minimum=90)
    await p.pull()
    url_str = str(route.calls[0].request.url)
    assert "90" in url_str


async def test_pull_non_200_returns_empty(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get(_BLACKLIST_URL).mock(return_value=httpx.Response(429))
    p = aip_mod.AbuseIPDBProvider("default")
    assert await p.pull() == []


async def test_pull_filters_by_since(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get(_BLACKLIST_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    _ip_entry("1.1.1.1", last_reported="2023-06-01T00:00:00+00:00"),  # old
                    _ip_entry("2.2.2.2", last_reported="2026-02-15T12:00:00+00:00"),  # recent
                ]
            },
        )
    )
    since = datetime(2024, 1, 1, tzinfo=UTC)
    p = aip_mod.AbuseIPDBProvider("default")
    records = await p.pull(since=since)
    assert len(records) == 1
    assert records[0].value == "2.2.2.2"


async def test_pull_context_includes_isp_and_usage(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get(_BLACKLIST_URL).mock(
        return_value=httpx.Response(
            200,
            json={"data": [_ip_entry("3.3.3.3", isp="Evil Corp", usage="VPN")]},
        )
    )
    p = aip_mod.AbuseIPDBProvider("default")
    records = await p.pull()
    assert records[0].context == "Evil Corp / VPN"


# ---------------------------------------------------------------------------
# health_check()
# ---------------------------------------------------------------------------


async def test_health_check_ok(respx_router: respx.Router, fake_secrets_with_token: None) -> None:
    respx_router.get(_CHECK_URL).mock(
        return_value=httpx.Response(
            200,
            json={"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0}},
        )
    )
    p = aip_mod.AbuseIPDBProvider("default")
    status = await p.health_check()
    assert status.ok is True
    assert "8.8.8.8" in status.detail
    assert "score=0" in status.detail


async def test_health_check_401(respx_router: respx.Router, fake_secrets_with_token: None) -> None:
    respx_router.get(_CHECK_URL).mock(return_value=httpx.Response(401))
    p = aip_mod.AbuseIPDBProvider("default")
    status = await p.health_check()
    assert status.ok is False
    assert "401" in status.detail


async def test_health_check_no_token(fake_secrets_no_token: None) -> None:
    p = aip_mod.AbuseIPDBProvider("default")
    status = await p.health_check()
    assert status.ok is False
