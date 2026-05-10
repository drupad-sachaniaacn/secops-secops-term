"""OTX provider — pulse pull + /users/me probe."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from types import ModuleType

import httpx
import pytest
import respx

from secops_term.core import secrets as secrets_mod
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers import otx as otx_mod
from secops_term.intel.providers.base import IntelProviderError

# Fixtures


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _make_fake_keyring(token: str | None = "test-otx-token") -> ModuleType:
    class _FakeBackend:
        pass

    backend = _FakeBackend()
    store: dict[tuple[str, str], str] = {}
    if token is not None:
        store[("secops-term:intel.otx:default", "api_token")] = token

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


# Registry


def test_registered() -> None:
    assert "otx" in PROVIDERS
    assert PROVIDERS.get("otx") is otx_mod.OTXProvider


def test_from_config_ignores_extra_keys() -> None:
    p = otx_mod.OTXProvider.from_config("default", {"some": "future-key", "another": 42})
    assert p.instance == "default"


# Auth


async def test_pull_without_token_raises(
    fake_secrets_no_token: None,
) -> None:
    p = otx_mod.OTXProvider("default")
    with pytest.raises(IntelProviderError):
        await p.pull()


# Pull


async def test_pull_maps_indicator_types(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "id": "pulse-1",
                        "name": "Emotet C2 List",
                        "tags": ["emotet"],
                        "indicators": [
                            {"type": "IPv4", "indicator": "1.2.3.4"},
                            {
                                "type": "domain",
                                "indicator": "evil.example.com",
                            },
                            {
                                "type": "URL",
                                "indicator": "https://evil.example.com/c2",
                            },
                            {
                                "type": "FileHash-SHA256",
                                "indicator": "a" * 64,
                            },
                            {"type": "FileHash-MD5", "indicator": "c" * 32},
                            {"type": "CVE", "indicator": "CVE-2024-1234"},
                            {"type": "UnknownType", "indicator": "skipped"},
                        ],
                    }
                ]
            },
        )
    )
    p = otx_mod.OTXProvider("default")
    records = await p.pull()
    by_type = {r.type for r in records}
    assert {"ipv4", "domain", "url", "sha256", "md5", "cve"} == by_type
    # All records share the pulse name as context (truncated to 200 chars).
    assert all(r.context == "Emotet C2 List" for r in records)
    assert all(r.source_ref == "pulse-1" for r in records)
    assert all(r.tags == ("emotet",) for r in records)
    assert all(r.source == "otx:default" for r in records)


async def test_pull_passes_auth_header(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    route = respx_router.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    p = otx_mod.OTXProvider("default")
    await p.pull()
    headers = route.calls[0].request.headers
    assert headers.get("X-OTX-API-KEY") == "test-otx-token"


async def test_pull_passes_modified_since(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    route = respx_router.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    since = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
    p = otx_mod.OTXProvider("default")
    await p.pull(since=since)
    request = route.calls[0].request
    assert "modified_since=2026-01-15T12%3A00%3A00" in str(request.url)


async def test_pull_handles_non_200(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
        return_value=httpx.Response(500)
    )
    p = otx_mod.OTXProvider("default")
    assert await p.pull() == []


async def test_hostname_maps_to_domain(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "id": "p1",
                        "name": "x",
                        "tags": [],
                        "indicators": [
                            {
                                "type": "hostname",
                                "indicator": "host.evil.example.com",
                            },
                        ],
                    }
                ]
            },
        )
    )
    p = otx_mod.OTXProvider("default")
    records = await p.pull()
    assert any(r.type == "domain" and "evil.example.com" in r.value for r in records)


# Health check


async def test_health_check_succeeds(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get("https://otx.alienvault.com/api/v1/users/me").mock(
        return_value=httpx.Response(200, json={"username": "soc-team"})
    )
    p = otx_mod.OTXProvider("default")
    status = await p.health_check()
    assert status.ok is True
    assert "soc-team" in status.detail


async def test_health_check_fails_on_401(
    respx_router: respx.Router, fake_secrets_with_token: None
) -> None:
    respx_router.get("https://otx.alienvault.com/api/v1/users/me").mock(
        return_value=httpx.Response(401)
    )
    p = otx_mod.OTXProvider("default")
    status = await p.health_check()
    assert status.ok is False
    assert "401" in status.detail


async def test_health_check_fails_without_token(
    fake_secrets_no_token: None,
) -> None:
    p = otx_mod.OTXProvider("default")
    status = await p.health_check()
    assert status.ok is False
