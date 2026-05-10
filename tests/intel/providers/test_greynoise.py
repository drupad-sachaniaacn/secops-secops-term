"""GreyNoise provider — GNQL pull + /ping health probe."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from types import ModuleType

import httpx
import pytest
import respx

from secops_term.core import secrets as secrets_mod
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers import greynoise as gn_mod
from secops_term.intel.providers.base import IntelProviderError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _make_fake_keyring(token: str | None = "test-gn-key") -> ModuleType:
    class _FakeBackend:
        pass

    backend = _FakeBackend()
    store: dict[tuple[str, str], str] = {}
    if token is not None:
        store[("secops-term:intel.greynoise:default", "api_key")] = token

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


_GN_GNQL_URL = "https://api.greynoise.io/v2/experimental/gnql"
_GN_PING_URL = "https://api.greynoise.io/ping"


def _ip_entry(
    ip: str = "1.2.3.4",
    classification: str = "malicious",
    name: str = "Mirai",
    tags: list[str] | None = None,
    last_seen: str = "2026-01-15",
) -> dict:
    return {
        "ip": ip,
        "classification": classification,
        "name": name,
        "tags": tags or ["mirai", "bot"],
        "last_seen": last_seen,
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registered() -> None:
    assert "greynoise" in PROVIDERS
    assert PROVIDERS.get("greynoise") is gn_mod.GreyNoiseProvider


# ---------------------------------------------------------------------------
# from_config
# ---------------------------------------------------------------------------


def test_from_config_defaults() -> None:
    p = gn_mod.GreyNoiseProvider.from_config("default", {})
    assert p.instance == "default"
    assert p._query == gn_mod._DEFAULT_QUERY
    assert p._limit == gn_mod._DEFAULT_LIMIT


def test_from_config_custom_query_limit() -> None:
    p = gn_mod.GreyNoiseProvider.from_config(
        "prod",
        {"query": "classification:malicious tags:mirai", "limit": 250},
    )
    assert p._query == "classification:malicious tags:mirai"
    assert p._limit == 250


def test_from_config_clamps_limit() -> None:
    p = gn_mod.GreyNoiseProvider.from_config("default", {"limit": 5000})
    assert p._limit == 1000  # capped at max


# ---------------------------------------------------------------------------
# pull()
# ---------------------------------------------------------------------------


async def test_pull_without_token_raises(fake_secrets_no_token: None) -> None:
    p = gn_mod.GreyNoiseProvider("default")
    with pytest.raises(IntelProviderError):
        await p.pull()


async def test_pull_maps_ips(respx_router: respx.Router, fake_secrets_with_token: None) -> None:
    respx_router.get(_GN_GNQL_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "complete": True,
                "count": 2,
                "data": [
                    _ip_entry("1.2.3.4", tags=["scanner"]),
                    _ip_entry("5.6.7.8", name="", tags=[]),
                ],
            },
        )
    )
    p = gn_mod.GreyNoiseProvider("default")
    records = await p.pull()
    assert len(records) == 2
    assert all(r.type == "ipv4" for r in records)
    assert {r.value for r in records} == {"1.2.3.4", "5.6.7.8"}
    assert all(r.source == "greynoise:default" for r in records)


async def test_pull_sends_key_header(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    route = respx_router.get(_GN_GNQL_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    p = gn_mod.GreyNoiseProvider("default")
    await p.pull()
    assert route.calls[0].request.headers.get("key") == "test-gn-key"


async def test_pull_sends_gnql_params(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    route = respx_router.get(_GN_GNQL_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    p = gn_mod.GreyNoiseProvider("default", query="classification:malicious tags:mirai", limit=50)
    await p.pull()
    url_str = str(route.calls[0].request.url)
    assert "50" in url_str


async def test_pull_401_returns_empty(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get(_GN_GNQL_URL).mock(return_value=httpx.Response(401))
    p = gn_mod.GreyNoiseProvider("default")
    assert await p.pull() == []


async def test_pull_non_200_returns_empty(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get(_GN_GNQL_URL).mock(return_value=httpx.Response(500))
    p = gn_mod.GreyNoiseProvider("default")
    assert await p.pull() == []


async def test_pull_context_includes_classification_and_name(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get(_GN_GNQL_URL).mock(
        return_value=httpx.Response(
            200,
            json={"data": [_ip_entry("9.9.9.9", classification="malicious", name="Mirai")]},
        )
    )
    p = gn_mod.GreyNoiseProvider("default")
    records = await p.pull()
    assert records[0].context == "malicious / Mirai"


async def test_pull_filters_by_since_date(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get(_GN_GNQL_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    _ip_entry("1.1.1.1", last_seen="2023-05-01"),  # too old
                    _ip_entry("2.2.2.2", last_seen="2026-03-01"),  # recent
                ]
            },
        )
    )
    since = datetime(2024, 1, 1, tzinfo=UTC)
    p = gn_mod.GreyNoiseProvider("default")
    records = await p.pull(since=since)
    assert len(records) == 1
    assert records[0].value == "2.2.2.2"


# ---------------------------------------------------------------------------
# health_check()
# ---------------------------------------------------------------------------


async def test_health_check_ok(respx_router: respx.Router, fake_secrets_with_token: None) -> None:
    respx_router.get(_GN_PING_URL).mock(
        return_value=httpx.Response(200, json={"message": "pong", "offering": "enterprise"})
    )
    p = gn_mod.GreyNoiseProvider("default")
    status = await p.health_check()
    assert status.ok is True
    assert "enterprise" in status.detail


async def test_health_check_community_tier(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get(_GN_PING_URL).mock(
        return_value=httpx.Response(200, json={"message": "pong", "offering": "community"})
    )
    p = gn_mod.GreyNoiseProvider("default")
    status = await p.health_check()
    assert status.ok is True
    assert "community" in status.detail


async def test_health_check_401(respx_router: respx.Router, fake_secrets_with_token: None) -> None:
    respx_router.get(_GN_PING_URL).mock(return_value=httpx.Response(401))
    p = gn_mod.GreyNoiseProvider("default")
    status = await p.health_check()
    assert status.ok is False
    assert "401" in status.detail


async def test_health_check_no_token(fake_secrets_no_token: None) -> None:
    p = gn_mod.GreyNoiseProvider("default")
    status = await p.health_check()
    assert status.ok is False
