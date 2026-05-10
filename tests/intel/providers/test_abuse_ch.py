"""abuse.ch provider — sub-feed pulls + auth-key probe."""

from __future__ import annotations

import json
from collections.abc import Iterator

import httpx
import pytest
import respx

from secops_term.core import secrets as secrets_mod
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers import abuse_ch as abuse_mod
from secops_term.intel.providers.base import IntelProviderError

# Fixtures


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _make_fake_keyring(token: str | None = "test-abuse-token"):
    """Inject a fake keyring backed module so SecretsManager uses it."""
    from types import ModuleType

    class _FakeBackend:
        pass

    backend = _FakeBackend()
    store: dict[tuple[str, str], str] = {}
    if token is not None:
        store[("secops-term:intel.abuse_ch:default", "api_token")] = token

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


# Registry / construction


def test_registered() -> None:
    assert "abuse_ch" in PROVIDERS
    assert PROVIDERS.get("abuse_ch") is abuse_mod.AbuseCHProvider


def test_from_config_default_sub_feeds() -> None:
    p = abuse_mod.AbuseCHProvider.from_config("default", {})
    assert p.sub_feeds == (
        "urlhaus",
        "malware_bazaar",
        "threatfox",
        "feodo_tracker",
    )


def test_from_config_custom_sub_feeds() -> None:
    p = abuse_mod.AbuseCHProvider.from_config("default", {"sub_feeds": ["urlhaus", "threatfox"]})
    assert p.sub_feeds == ("urlhaus", "threatfox")


def test_from_config_rejects_unknown_sub_feed() -> None:
    with pytest.raises(IntelProviderError):
        abuse_mod.AbuseCHProvider.from_config("default", {"sub_feeds": ["urlhaus", "not-a-feed"]})


def test_from_config_rejects_non_list_sub_feeds() -> None:
    with pytest.raises(IntelProviderError):
        abuse_mod.AbuseCHProvider.from_config("default", {"sub_feeds": "urlhaus,threatfox"})


# Auth required


async def test_pull_without_token_raises(
    fake_secrets_no_token: None,
) -> None:
    p = abuse_mod.AbuseCHProvider("default")
    with pytest.raises(IntelProviderError):
        await p.pull()


async def test_health_without_token_returns_failed(
    fake_secrets_no_token: None,
) -> None:
    p = abuse_mod.AbuseCHProvider("default")
    status = await p.health_check()
    assert status.ok is False
    assert "no api_token" in status.detail


# URLhaus


async def test_pull_urlhaus_returns_url_records(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.post("https://urlhaus-api.abuse.ch/v1/urls/recent/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "urls": [
                    {
                        "id": "1",
                        "url": "https://evil.example.com/malware.exe",
                        "tags": ["emotet", "exe"],
                        "threat": "malware_download",
                    },
                    {
                        "id": "2",
                        "url": "https://attacker.example.org/phish",
                        "tags": ["phishing"],
                        "threat": "phishing",
                    },
                ],
            },
        )
    )
    p = abuse_mod.AbuseCHProvider("default", sub_feeds=("urlhaus",))
    records = await p.pull()
    urls = [r for r in records if r.type == "url"]
    assert len(urls) == 2
    values = {r.value for r in urls}
    assert "https://evil.example.com/malware.exe" in values
    assert "https://attacker.example.org/phish" in values
    assert all(r.source == "abuse_ch:default" for r in urls)
    assert all("emotet" in r.tags or "phishing" in r.tags for r in urls)


async def test_pull_urlhaus_sends_auth_header(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    route = respx_router.post("https://urlhaus-api.abuse.ch/v1/urls/recent/").mock(
        return_value=httpx.Response(200, json={"query_status": "ok", "urls": []})
    )
    p = abuse_mod.AbuseCHProvider("default", sub_feeds=("urlhaus",))
    await p.pull()
    request = route.calls[0].request
    assert request.headers.get("Auth-Key") == "test-abuse-token"


# MalwareBazaar


async def test_pull_mbazaar_emits_three_hashes_per_sample(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.post("https://mb-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "sha256_hash": "a" * 64,
                        "sha1_hash": "b" * 40,
                        "md5_hash": "c" * 32,
                        "file_name": "loader.exe",
                        "signature": "Emotet",
                        "tags": ["emotet"],
                    }
                ],
            },
        )
    )
    p = abuse_mod.AbuseCHProvider("default", sub_feeds=("malware_bazaar",))
    records = await p.pull()
    types = {r.type for r in records}
    assert types == {"sha256", "sha1", "md5"}
    values = {r.value for r in records}
    assert "a" * 64 in values
    assert "b" * 40 in values
    assert "c" * 32 in values


async def test_pull_mbazaar_handles_no_results(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.post("https://mb-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results", "data": []})
    )
    p = abuse_mod.AbuseCHProvider("default", sub_feeds=("malware_bazaar",))
    assert await p.pull() == []


# ThreatFox


async def test_pull_threatfox_maps_ioc_types(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "id": "1",
                        "ioc": "1.2.3.4:443",
                        "ioc_type": "ip:port",
                        "confidence_level": 90,
                        "malware_printable": "Emotet",
                        "tags": ["c2"],
                    },
                    {
                        "id": "2",
                        "ioc": "evil.example.com",
                        "ioc_type": "domain",
                        "confidence_level": 80,
                        "malware_printable": "TrickBot",
                        "tags": [],
                    },
                    {
                        "id": "3",
                        "ioc": "a" * 64,
                        "ioc_type": "sha256_hash",
                        "confidence_level": 100,
                        "malware_printable": "QakBot",
                        "tags": [],
                    },
                ],
            },
        )
    )
    p = abuse_mod.AbuseCHProvider("default", sub_feeds=("threatfox",))
    records = await p.pull()
    by_type = {r.type: r for r in records}
    assert "ipv4" in by_type
    assert by_type["ipv4"].value == "1.2.3.4"  # port stripped
    assert by_type["domain"].value == "evil.example.com"
    assert by_type["sha256"].value == "a" * 64
    assert by_type["ipv4"].confidence == 90


async def test_pull_threatfox_drops_unknown_types(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "id": "1",
                        "ioc": "weird-thing",
                        "ioc_type": "unknown_type",
                    }
                ],
            },
        )
    )
    p = abuse_mod.AbuseCHProvider("default", sub_feeds=("threatfox",))
    assert await p.pull() == []


# Feodo Tracker


async def test_pull_feodo_returns_ipv4_records(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "ip_address": "1.2.3.4",
                    "port": 443,
                    "malware": "Emotet",
                    "first_seen": "2026-01-01",
                },
                {
                    "ip_address": "5.6.7.8",
                    "port": 80,
                    "malware": "TrickBot",
                },
            ],
        )
    )
    p = abuse_mod.AbuseCHProvider("default", sub_feeds=("feodo_tracker",))
    records = await p.pull()
    assert all(r.type == "ipv4" for r in records)
    values = {r.value for r in records}
    assert {"1.2.3.4", "5.6.7.8"} == values
    assert all("feodo_tracker" in r.tags for r in records)


# Sub-feed isolation


async def test_one_subfeed_failure_does_not_block_others(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    # URLhaus 500s; ThreatFox returns data.
    respx_router.post("https://urlhaus-api.abuse.ch/v1/urls/recent/").mock(
        return_value=httpx.Response(500)
    )
    respx_router.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "id": "1",
                        "ioc": "evil.example.com",
                        "ioc_type": "domain",
                        "confidence_level": 80,
                    }
                ],
            },
        )
    )
    p = abuse_mod.AbuseCHProvider("default", sub_feeds=("urlhaus", "threatfox"))
    records = await p.pull()
    assert any(r.type == "domain" and r.value == "evil.example.com" for r in records)


# Health check


async def test_health_check_succeeds(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "ok", "data": []})
    )
    p = abuse_mod.AbuseCHProvider("default")
    status = await p.health_check()
    assert status.ok is True


async def test_health_check_fails_on_401(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(401, text="bad token")
    )
    p = abuse_mod.AbuseCHProvider("default")
    status = await p.health_check()
    assert status.ok is False
    assert "401" in status.detail


async def test_health_check_fails_on_bad_query_status(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "rate_limited"})
    )
    p = abuse_mod.AbuseCHProvider("default")
    status = await p.health_check()
    assert status.ok is False
    assert "rate_limited" in status.detail


# Smoke: silence linter on json import
_ = json
