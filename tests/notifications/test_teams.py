"""Microsoft Teams notifier — webhook URL in keyring, MessageCard payload."""

from __future__ import annotations

import json
from collections.abc import Iterator
from types import ModuleType

import httpx
import pytest
import respx

from secops_term.core import secrets as secrets_mod
from secops_term.notifications import NotifyPayload
from secops_term.notifications.base import NotifierError
from secops_term.notifications.teams import TeamsNotifier


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


_TEAMS_URL = "https://acme.webhook.office.com/webhookb2/abc/IncomingWebhook/xyz/123"


@pytest.fixture
def fake_secrets_with_webhook() -> Iterator[None]:
    secrets_mod.reset_manager_for_tests()
    fake = _fake_keyring(
        {("secops-term:notifications.teams:incident-response", "webhook_url"): _TEAMS_URL}
    )
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


@pytest.fixture
def fake_secrets_no_webhook() -> Iterator[None]:
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=_fake_keyring({})))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


def _payload(severity: str = "error") -> NotifyPayload:
    return NotifyPayload(
        summary="Incident triggered",
        body="Detection rule fired.",
        severity=severity,
        context={"playbook": "high-conf-ioc-followup", "ioc": "1.2.3.4"},
    )


# from_config


def test_from_config_accepts_empty_block() -> None:
    n = TeamsNotifier.from_config("incident-response", {})
    assert n.instance == "incident-response"


def test_from_config_rejects_url_in_toml() -> None:
    with pytest.raises(NotifierError):
        TeamsNotifier.from_config("incident-response", {"url": _TEAMS_URL})


# send


async def test_send_success(
    fake_secrets_with_webhook: None,
    respx_router: respx.Router,
) -> None:
    route = respx_router.post(_TEAMS_URL).mock(return_value=httpx.Response(200, text="1"))
    n = TeamsNotifier("incident-response")
    result = await n.send(_payload())
    assert result.delivered is True
    body = json.loads(route.calls[0].request.content)
    assert body["@type"] == "MessageCard"
    assert body["title"] == "Incident triggered"
    # Severity error → red.
    assert body["themeColor"] == "D13438"
    # Context surfaces as facts.
    facts = body["sections"][0]["facts"]
    assert any(f["name"] == "playbook" for f in facts)


async def test_send_severity_colors() -> None:
    n = TeamsNotifier("x")
    info = n._render(_payload("info"))
    warn = n._render(_payload("warn"))
    error = n._render(_payload("error"))
    assert info["themeColor"] == "107C10"
    assert warn["themeColor"] == "FF8C00"
    assert error["themeColor"] == "D13438"


async def test_send_no_webhook_returns_undelivered(
    fake_secrets_no_webhook: None,
) -> None:
    n = TeamsNotifier("incident-response")
    result = await n.send(_payload())
    assert result.delivered is False
    assert "webhook URL" in result.detail


async def test_send_teams_non_one_response_fails(
    fake_secrets_with_webhook: None,
    respx_router: respx.Router,
) -> None:
    """Teams returns 200 with body '1' on success; anything else fails."""
    respx_router.post(_TEAMS_URL).mock(return_value=httpx.Response(200, text="error: malformed"))
    n = TeamsNotifier("incident-response")
    result = await n.send(_payload())
    assert result.delivered is False


# health_check


async def test_health_check_ok(
    fake_secrets_with_webhook: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post(_TEAMS_URL).mock(return_value=httpx.Response(200, text="1"))
    n = TeamsNotifier("incident-response")
    h = await n.health_check()
    assert h.ok is True


async def test_health_check_no_webhook(
    fake_secrets_no_webhook: None,
) -> None:
    n = TeamsNotifier("incident-response")
    h = await n.health_check()
    assert h.ok is False
