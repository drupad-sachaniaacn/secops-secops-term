"""VirusTotal provider — Intelligence Search pull + /users/{owner} health probe."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from types import ModuleType

import httpx
import pytest
import respx

from secops_term.core import secrets as secrets_mod
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers import virustotal as vt_mod
from secops_term.intel.providers.base import IntelProviderError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _make_fake_keyring(token: str | None = "test-vt-key") -> ModuleType:
    class _FakeBackend:
        pass

    backend = _FakeBackend()
    store: dict[tuple[str, str], str] = {}
    if token is not None:
        store[("secops-term:intel.virustotal:default", "api_key")] = token

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


# Helpers
_VT_SEARCH_URL = "https://www.virustotal.com/api/v3/intelligence/search"
_VT_USERS_URL = "https://www.virustotal.com/api/v3/users/soc-team"


def _file_obj(
    sha256: str = "a" * 64,
    sha1: str = "b" * 40,
    md5: str = "c" * 32,
    last_sub: int = 1_700_000_000,
    tags: list[str] | None = None,
    label: str = "trojan.mikey",
) -> dict:
    return {
        "id": sha256,
        "type": "file",
        "attributes": {
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "last_submission_date": last_sub,
            "tags": tags or ["malware"],
            "popular_threat_classification": {"suggested_threat_label": label},
        },
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registered() -> None:
    assert "virustotal" in PROVIDERS
    assert PROVIDERS.get("virustotal") is vt_mod.VirusTotalProvider


# ---------------------------------------------------------------------------
# from_config
# ---------------------------------------------------------------------------


def test_from_config_defaults() -> None:
    p = vt_mod.VirusTotalProvider.from_config("default", {})
    assert p.instance == "default"
    assert p._owner == ""
    assert p._query == vt_mod._DEFAULT_QUERY
    assert p._limit == vt_mod._DEFAULT_LIMIT


def test_from_config_parses_all_fields() -> None:
    p = vt_mod.VirusTotalProvider.from_config(
        "prod",
        {"owner": "soc-team", "query": "type:malware p:10+", "limit": 80},
    )
    assert p._owner == "soc-team"
    assert p._query == "type:malware p:10+"
    assert p._limit == 80


def test_from_config_clamps_limit() -> None:
    p = vt_mod.VirusTotalProvider.from_config("default", {"limit": 9999})
    assert p._limit == 300  # capped at max


# ---------------------------------------------------------------------------
# pull()
# ---------------------------------------------------------------------------


async def test_pull_without_token_raises(fake_secrets_no_token: None) -> None:
    p = vt_mod.VirusTotalProvider("default", owner="soc")
    with pytest.raises(IntelProviderError):
        await p.pull()


async def test_pull_maps_hashes(respx_router: respx.Router, fake_secrets_with_token: None) -> None:
    respx_router.get(_VT_SEARCH_URL).mock(
        return_value=httpx.Response(200, json={"data": [_file_obj()]})
    )
    p = vt_mod.VirusTotalProvider("default")
    records = await p.pull()
    # Three hashes per file object.
    assert len(records) == 3
    types = {r.type for r in records}
    assert types == {"sha256", "sha1", "md5"}
    assert all(r.source == "virustotal:default" for r in records)
    assert all(r.context == "trojan.mikey" for r in records)
    assert all(r.tags == ("malware",) for r in records)


async def test_pull_sends_auth_header(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    route = respx_router.get(_VT_SEARCH_URL).mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    p = vt_mod.VirusTotalProvider("default")
    await p.pull()
    assert route.calls[0].request.headers.get("x-apikey") == "test-vt-key"


async def test_pull_sends_query_params(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    route = respx_router.get(_VT_SEARCH_URL).mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    p = vt_mod.VirusTotalProvider("default", query="type:malware p:10+", limit=25)
    await p.pull()
    url_str = str(route.calls[0].request.url)
    assert "type%3Amalware" in url_str or "type:malware" in url_str
    assert "25" in url_str


async def test_pull_403_returns_empty(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get(_VT_SEARCH_URL).mock(return_value=httpx.Response(403))
    p = vt_mod.VirusTotalProvider("default")
    assert await p.pull() == []


async def test_pull_non_200_returns_empty(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get(_VT_SEARCH_URL).mock(return_value=httpx.Response(500))
    p = vt_mod.VirusTotalProvider("default")
    assert await p.pull() == []


async def test_pull_filters_by_since(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    old_ts = 1_600_000_000  # epoch 2020
    new_ts = 1_750_000_000  # epoch ~2025
    respx_router.get(_VT_SEARCH_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    _file_obj(sha256="a" * 64, last_sub=old_ts),
                    _file_obj(sha256="b" * 64, sha1="c" * 40, md5="d" * 32, last_sub=new_ts),
                ]
            },
        )
    )
    since = datetime(2024, 1, 1, tzinfo=UTC)
    p = vt_mod.VirusTotalProvider("default")
    records = await p.pull(since=since)
    # Only the newer file's hashes should appear.
    assert all(r.value != "a" * 64 for r in records)


# ---------------------------------------------------------------------------
# health_check()
# ---------------------------------------------------------------------------


async def test_health_check_ok(respx_router: respx.Router, fake_secrets_with_token: None) -> None:
    respx_router.get(_VT_USERS_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {"quotas": {"api_requests_daily": {"used": 120, "allowed": 1000}}}
                }
            },
        )
    )
    p = vt_mod.VirusTotalProvider("default", owner="soc-team")
    status = await p.health_check()
    assert status.ok is True
    assert "auth ok" in status.detail
    assert "120/1000" in status.detail


async def test_health_check_no_owner(fake_secrets_with_token: None) -> None:
    p = vt_mod.VirusTotalProvider("default", owner="")
    status = await p.health_check()
    assert status.ok is False
    assert "owner not configured" in status.detail


async def test_health_check_401(respx_router: respx.Router, fake_secrets_with_token: None) -> None:
    respx_router.get(_VT_USERS_URL).mock(return_value=httpx.Response(401))
    p = vt_mod.VirusTotalProvider("default", owner="soc-team")
    status = await p.health_check()
    assert status.ok is False
    assert "401" in status.detail


async def test_health_check_no_token(fake_secrets_no_token: None) -> None:
    p = vt_mod.VirusTotalProvider("default", owner="soc-team")
    status = await p.health_check()
    assert status.ok is False
