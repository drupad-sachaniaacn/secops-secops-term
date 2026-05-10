"""Generic-JSON notifier — POSTs an envelope to a configured URL."""

from __future__ import annotations

from collections.abc import Iterator
from types import ModuleType

import httpx
import pytest
import respx

from secops_term.core import secrets as secrets_mod
from secops_term.notifications import NotifyPayload
from secops_term.notifications.base import NotifierError
from secops_term.notifications.generic_json import GenericJsonNotifier


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _fake_keyring(entries: dict[tuple[str, str], str]) -> ModuleType:
    class _Backend:
        pass

    backend = _Backend()
    store: dict[tuple[str, str], str] = dict(entries)

    def get_keyring() -> _Backend:
        return backend

    def set_password(s: str, k: str, v: str) -> None:
        store[(s, k)] = v

    def get_password(s: str, k: str) -> str | None:
        return store.get((s, k))

    def delete_password(s: str, k: str) -> None:
        store.pop((s, k), None)

    mod = ModuleType("fake_keyring")
    mod.get_keyring = get_keyring  # type: ignore[attr-defined]
    mod.set_password = set_password  # type: ignore[attr-defined]
    mod.get_password = get_password  # type: ignore[attr-defined]
    mod.delete_password = delete_password  # type: ignore[attr-defined]
    return mod


@pytest.fixture
def fake_secrets_no_entries() -> Iterator[None]:
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=_fake_keyring({})))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


@pytest.fixture
def fake_secrets_with_bearer() -> Iterator[None]:
    secrets_mod.reset_manager_for_tests()
    fake = _fake_keyring(
        {("secops-term:notifications.generic_json:default", "bearer_token"): "tok-123"}
    )
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


@pytest.fixture
def fake_secrets_url_in_keyring() -> Iterator[None]:
    secrets_mod.reset_manager_for_tests()
    fake = _fake_keyring(
        {
            (
                "secops-term:notifications.generic_json:default",
                "url",
            ): "https://hooks.example.com/secret"
        }
    )
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


def _payload(severity: str = "info") -> NotifyPayload:
    return NotifyPayload(summary="title", body="body text", severity=severity, context={"k": "v"})


# from_config


def test_from_config_default_template() -> None:
    n = GenericJsonNotifier.from_config("default", {"url": "https://hooks.example.com/x"})
    assert n.template == "standard"


def test_from_config_compact_template() -> None:
    n = GenericJsonNotifier.from_config("default", {"url": "https://h/", "template": "compact"})
    assert n.template == "compact"


def test_from_config_unknown_template_rejected() -> None:
    with pytest.raises(NotifierError):
        GenericJsonNotifier.from_config("default", {"url": "https://h/", "template": "fancy"})


def test_from_config_non_string_url_rejected() -> None:
    with pytest.raises(NotifierError):
        GenericJsonNotifier.from_config("default", {"url": 42})


# send


async def test_send_success_200(
    fake_secrets_no_entries: None,
    respx_router: respx.Router,
) -> None:
    route = respx_router.post("https://hooks.example.com/x").mock(
        return_value=httpx.Response(200, text="ok")
    )
    n = GenericJsonNotifier("default", url="https://hooks.example.com/x")
    result = await n.send(_payload())
    assert result.delivered is True
    assert "200" in result.detail
    # Standard envelope shape.
    body = route.calls[0].request.content.decode()
    assert "secops-terminal" in body
    assert "title" in body
    assert "body text" in body


async def test_send_compact_envelope(
    fake_secrets_no_entries: None,
    respx_router: respx.Router,
) -> None:
    route = respx_router.post("https://h/").mock(return_value=httpx.Response(204))
    n = GenericJsonNotifier("default", url="https://h/", template="compact")
    await n.send(_payload())
    body = route.calls[0].request.content.decode()
    # Compact has only summary/severity/body; no source/context.
    assert "summary" in body
    assert "severity" in body
    assert "secops-terminal" not in body
    assert "context" not in body


async def test_send_includes_bearer_when_in_keyring(
    fake_secrets_with_bearer: None,
    respx_router: respx.Router,
) -> None:
    route = respx_router.post("https://h/").mock(return_value=httpx.Response(200, text="ok"))
    n = GenericJsonNotifier("default", url="https://h/")
    await n.send(_payload())
    auth = route.calls[0].request.headers.get("authorization")
    assert auth == "Bearer tok-123"


async def test_send_omits_bearer_when_none(
    fake_secrets_no_entries: None,
    respx_router: respx.Router,
) -> None:
    route = respx_router.post("https://h/").mock(return_value=httpx.Response(200, text="ok"))
    n = GenericJsonNotifier("default", url="https://h/")
    await n.send(_payload())
    assert "authorization" not in {k.lower() for k in route.calls[0].request.headers}


async def test_send_5xx_returns_undelivered(
    fake_secrets_no_entries: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://h/").mock(return_value=httpx.Response(500, text="server down"))
    n = GenericJsonNotifier("default", url="https://h/")
    result = await n.send(_payload())
    assert result.delivered is False
    assert "500" in result.detail


async def test_send_no_url_returns_undelivered(
    fake_secrets_no_entries: None,
) -> None:
    n = GenericJsonNotifier("default", url=None)
    result = await n.send(_payload())
    assert result.delivered is False
    assert "no url configured" in result.detail


async def test_send_url_from_keyring(
    fake_secrets_url_in_keyring: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://hooks.example.com/secret").mock(
        return_value=httpx.Response(200, text="ok")
    )
    n = GenericJsonNotifier("default", url=None)
    result = await n.send(_payload())
    assert result.delivered is True


# health_check


async def test_health_check_200_ok(
    fake_secrets_no_entries: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://h/").mock(return_value=httpx.Response(204))
    n = GenericJsonNotifier("default", url="https://h/")
    h = await n.health_check()
    assert h.ok is True


async def test_health_check_401_fails(
    fake_secrets_no_entries: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://h/").mock(return_value=httpx.Response(401))
    n = GenericJsonNotifier("default", url="https://h/")
    h = await n.health_check()
    assert h.ok is False
    assert "401" in h.detail


async def test_health_check_no_url_fails(
    fake_secrets_no_entries: None,
) -> None:
    n = GenericJsonNotifier("default", url=None)
    h = await n.health_check()
    assert h.ok is False
    assert "no url" in h.detail
