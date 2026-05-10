"""Notification orchestrator — discover, build, dispatch, health probes."""

from __future__ import annotations

from collections.abc import Iterator
from types import ModuleType

import httpx
import pytest
import respx

from secops_term.core import secrets as secrets_mod
from secops_term.notifications import NotifyPayload
from secops_term.notifications import orchestrator as orch
from secops_term.notifications.base import NotifierError


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
def secrets_with_slack_and_teams() -> Iterator[None]:
    secrets_mod.reset_manager_for_tests()
    fake = _fake_keyring(
        {
            ("secops-term:notifications.slack:soc-alerts", "webhook_url"): (
                "https://hooks.slack.com/services/T/B/X"
            ),
            ("secops-term:notifications.teams:incident-response", "webhook_url"): (
                "https://acme.webhook.office.com/webhookb2/a/IncomingWebhook/b/c"
            ),
        }
    )
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


# list_configured


def test_list_configured_walks_blocks() -> None:
    cfg = {
        "notifications": {
            "slack": {"soc-alerts": {}, "escalations": {}},
            "teams": {"incident-response": {}},
            "generic_json": {"internal-bot": {"url": "https://h/", "template": "compact"}},
        }
    }
    targets = orch.list_configured(cfg_data=cfg)
    channels = {t.channel for t in targets}
    assert channels == {
        "slack:soc-alerts",
        "slack:escalations",
        "teams:incident-response",
        "generic_json:internal-bot",
    }


def test_list_configured_empty_when_no_block() -> None:
    assert orch.list_configured(cfg_data={}) == []
    assert orch.list_configured(cfg_data={"notifications": {}}) == []


def test_list_configured_skips_non_mapping_entries() -> None:
    cfg = {
        "notifications": {
            "slack": "not-a-mapping",
            "teams": {"good": {}},
        }
    }
    targets = orch.list_configured(cfg_data=cfg)
    assert {t.channel for t in targets} == {"teams:good"}


# build_by_channel


def test_build_by_channel_slack() -> None:
    cfg = {"notifications": {"slack": {"soc-alerts": {}}}}
    notifier = orch.build_by_channel("slack:soc-alerts", cfg_data=cfg)
    assert notifier.name == "slack"
    assert notifier.instance == "soc-alerts"


def test_build_by_channel_unknown_channel_raises() -> None:
    cfg = {"notifications": {"slack": {"soc-alerts": {}}}}
    with pytest.raises(NotifierError):
        orch.build_by_channel("slack:other-room", cfg_data=cfg)


def test_build_by_channel_unknown_notifier_raises() -> None:
    cfg = {"notifications": {"discord": {"x": {}}}}
    with pytest.raises(NotifierError):
        orch.build_by_channel("discord:x", cfg_data=cfg)


@pytest.mark.parametrize("channel", ["bad-format", ":missing-name", "x:", ""])
def test_build_by_channel_malformed_string_raises(channel: str) -> None:
    cfg = {"notifications": {"slack": {"soc-alerts": {}}}}
    with pytest.raises(NotifierError):
        orch.build_by_channel(channel, cfg_data=cfg)


# dispatch


async def test_dispatch_slack(
    secrets_with_slack_and_teams: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://hooks.slack.com/services/T/B/X").mock(
        return_value=httpx.Response(200, text="ok")
    )
    cfg = {"notifications": {"slack": {"soc-alerts": {}}}}
    result = await orch.dispatch(
        "slack:soc-alerts",
        NotifyPayload(summary="x", body="y", severity="info", context={}),
        cfg_data=cfg,
    )
    assert result.delivered is True


async def test_dispatch_unknown_channel_raises(
    secrets_with_slack_and_teams: None,
) -> None:
    cfg = {"notifications": {}}
    with pytest.raises(NotifierError):
        await orch.dispatch(
            "slack:soc-alerts",
            NotifyPayload(summary="x", body="y", severity="info", context={}),
            cfg_data=cfg,
        )


# health_check_all


async def test_health_check_all_runs_concurrently(
    secrets_with_slack_and_teams: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://hooks.slack.com/services/T/B/X").mock(
        return_value=httpx.Response(200, text="ok")
    )
    respx_router.post("https://acme.webhook.office.com/webhookb2/a/IncomingWebhook/b/c").mock(
        return_value=httpx.Response(200, text="1")
    )
    cfg = {
        "notifications": {
            "slack": {"soc-alerts": {}},
            "teams": {"incident-response": {}},
        }
    }
    statuses = await orch.health_check_all(cfg_data=cfg)
    assert len(statuses) == 2
    assert all(s.ok for s in statuses)


async def test_health_check_all_empty_when_no_config() -> None:
    statuses = await orch.health_check_all(cfg_data={})
    assert statuses == []
