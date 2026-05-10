"""Notifier registry: NOTIFIERS exists, discover() works, no concretes shipped."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from secops_term import notifications
from secops_term.core.health import HealthStatus
from secops_term.notifications import base


def test_notifiers_registry_exists() -> None:
    assert notifications.NOTIFIERS.name == "notifiers"


def test_phase_5_ships_three_concrete_notifiers() -> None:
    """Phase 5 ships ``generic_json``, ``slack``, ``teams``."""
    notifications.discover()
    names = set(notifications.NOTIFIERS.keys())
    assert {"generic_json", "slack", "teams"}.issubset(names)


def test_register_and_lookup_test_notifier() -> None:
    @notifications.NOTIFIERS.register("test-notifier")
    class TestNotifier:
        name = "test-notifier"

        def __init__(self, instance: str, cfg: Mapping[str, Any]) -> None:
            self.instance = instance
            self._cfg = cfg

        @classmethod
        def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> base.Notifier:
            return cls(instance, cfg)

        async def send(self, payload: base.NotifyPayload) -> base.NotifyResult:
            return base.NotifyResult(delivered=True, detail="ok", latency_ms=1.0)

        async def health_check(self) -> HealthStatus:
            return HealthStatus(
                ok=True,
                latency_ms=1.0,
                detail="test",
                last_checked=datetime.now(UTC),
            )

    cls = notifications.NOTIFIERS.get("test-notifier")
    assert cls is TestNotifier

    inst = cls.from_config("default", {})
    assert isinstance(inst, base.Notifier)
    assert inst.instance == "default"
    assert inst.name == "test-notifier"


def test_notify_payload_dataclass() -> None:
    p = base.NotifyPayload(summary="title", body="body text", severity="info", context={})
    assert p.summary == "title"
    assert p.severity == "info"


def test_notify_payload_severity_warn() -> None:
    p = base.NotifyPayload(summary="title", body="body", severity="warn", context={"k": "v"})
    assert p.severity == "warn"
    assert p.context == {"k": "v"}


def test_notify_result_dataclass() -> None:
    r = base.NotifyResult(delivered=True, detail="ok", latency_ms=42.0)
    assert r.delivered is True
    assert r.latency_ms == 42.0


def test_notify_result_failure() -> None:
    r = base.NotifyResult(delivered=False, detail="HTTP 500 from webhook", latency_ms=12.5)
    assert r.delivered is False
    assert "500" in r.detail


def test_re_exports_match_base() -> None:
    assert notifications.Notifier is base.Notifier
    assert notifications.NotifierError is base.NotifierError
    assert notifications.NotifyPayload is base.NotifyPayload
    assert notifications.NotifyResult is base.NotifyResult
