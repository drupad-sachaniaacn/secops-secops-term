"""Slack notifier — webhook URL in keyring, MessageCard-attachment payload."""

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
from secops_term.notifications.slack import SlackNotifier


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
def fake_secrets_with_webhook() -> Iterator[None]:
    secrets_mod.reset_manager_for_tests()
    fake = _fake_keyring(
        {
            ("secops-term:notifications.slack:soc-alerts", "webhook_url"): (
                "https://hooks.slack.com/services/T/B/X"
            )
        }
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


def _payload(severity: str = "info") -> NotifyPayload:
    return NotifyPayload(
        summary="Brief title",
        body="Long body of the message.",
        severity=severity,
        context={"host": "WIN-01", "ip": "1.2.3.4"},
    )


# from_config


def test_from_config_accepts_empty_block() -> None:
    n = SlackNotifier.from_config("soc-alerts", {})
    assert n.instance == "soc-alerts"


def test_from_config_rejects_url_in_toml() -> None:
    with pytest.raises(NotifierError):
        SlackNotifier.from_config("soc-alerts", {"url": "https://hooks.slack.com/x"})


def test_from_config_rejects_webhook_url_alias_too() -> None:
    with pytest.raises(NotifierError):
        SlackNotifier.from_config("soc-alerts", {"webhook_url": "https://hooks.slack.com/x"})


# send


async def test_send_success(
    fake_secrets_with_webhook: None,
    respx_router: respx.Router,
) -> None:
    route = respx_router.post("https://hooks.slack.com/services/T/B/X").mock(
        return_value=httpx.Response(200, text="ok")
    )
    n = SlackNotifier("soc-alerts")
    result = await n.send(_payload(severity="warn"))
    assert result.delivered is True
    body = json.loads(route.calls[0].request.content)
    assert "attachments" in body
    att = body["attachments"][0]
    assert att["title"] == "Brief title"
    # Color picked from the severity map.
    assert att["color"] == "#ff9933"
    # Context fields surfaced (truncated).
    assert any(f["title"] == "host" for f in att["fields"])


async def test_send_severity_colors() -> None:
    """The color map is small enough to assert directly."""
    n = SlackNotifier("x")
    info = n._render(_payload("info"))["attachments"][0]
    warn = n._render(_payload("warn"))["attachments"][0]
    error = n._render(_payload("error"))["attachments"][0]
    assert info["color"] == "#36a64f"
    assert warn["color"] == "#ff9933"
    assert error["color"] == "#cc0000"


async def test_send_no_webhook_returns_undelivered(
    fake_secrets_no_webhook: None,
) -> None:
    n = SlackNotifier("soc-alerts")
    result = await n.send(_payload())
    assert result.delivered is False
    assert "webhook URL" in result.detail


async def test_send_slack_returns_non_ok_text_fails(
    fake_secrets_with_webhook: None,
    respx_router: respx.Router,
) -> None:
    """Slack-specific: 200 with body != 'ok' is a failure (e.g. invalid_payload)."""
    respx_router.post("https://hooks.slack.com/services/T/B/X").mock(
        return_value=httpx.Response(200, text="invalid_payload")
    )
    n = SlackNotifier("soc-alerts")
    result = await n.send(_payload())
    assert result.delivered is False
    assert "invalid_payload" in result.detail


async def test_send_5xx_returns_undelivered(
    fake_secrets_with_webhook: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://hooks.slack.com/services/T/B/X").mock(
        return_value=httpx.Response(500, text="oops")
    )
    n = SlackNotifier("soc-alerts")
    result = await n.send(_payload())
    assert result.delivered is False


# health_check


async def test_health_check_ok(
    fake_secrets_with_webhook: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://hooks.slack.com/services/T/B/X").mock(
        return_value=httpx.Response(200, text="ok")
    )
    n = SlackNotifier("soc-alerts")
    h = await n.health_check()
    assert h.ok is True


async def test_health_check_no_webhook(
    fake_secrets_no_webhook: None,
) -> None:
    n = SlackNotifier("soc-alerts")
    h = await n.health_check()
    assert h.ok is False
