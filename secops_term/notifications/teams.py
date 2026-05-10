"""Microsoft Teams Incoming-Webhook notifier (MessageCard format).

Per brief v3 §6.6: webhook URL is treated as a credential and lives in
the keyring (``secops-term:notifications.teams:<instance>`` /
``webhook_url``). The config-toml block carries no URL.

Severity → MessageCard ``themeColor``:

- ``info``  → ``"107C10"`` (green)
- ``warn``  → ``"FF8C00"`` (orange)
- ``error`` → ``"D13438"`` (red)

Note on format: Microsoft has been rolling out Adaptive Cards as the
replacement for the legacy MessageCard, but the legacy format still
works on every Teams tenant we care about and avoids tenant-specific
schema bugs. Bumping to Adaptive Cards is a one-spot edit when the
upstream cutover lands.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, ClassVar

from secops_term.core import secrets as secrets_mod
from secops_term.core.health import HealthStatus
from secops_term.core.http import HardenedClient
from secops_term.notifications import NOTIFIERS
from secops_term.notifications.base import (
    NotifierError,
    NotifyPayload,
    NotifyResult,
)

_KEYRING_PROVIDER = "notifications.teams"
_WEBHOOK_FIELD = "webhook_url"

_SEVERITY_THEME: dict[str, str] = {
    "info": "107C10",
    "warn": "FF8C00",
    "error": "D13438",
}


@NOTIFIERS.register("teams")
class TeamsNotifier:
    """Microsoft Teams Incoming-Webhook notifier."""

    name: ClassVar[str] = "teams"

    def __init__(self, instance: str) -> None:
        self.instance = instance

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> TeamsNotifier:
        if "url" in cfg or "webhook_url" in cfg:
            raise NotifierError(
                f"teams:{instance}: webhook URLs are credentials and must live in the "
                f"keyring under `{_KEYRING_PROVIDER}:{instance}/{_WEBHOOK_FIELD}`, "
                f"not config.toml"
            )
        return cls(instance)

    # Public API

    async def send(self, payload: NotifyPayload) -> NotifyResult:
        started = time.monotonic()
        try:
            url = self._get_webhook()
        except NotifierError as exc:
            return NotifyResult(
                delivered=False,
                detail=str(exc),
                latency_ms=_elapsed_ms(started),
            )
        body = self._render(payload)
        try:
            async with HardenedClient() as http:
                resp = await http.post(url, json=body)
        except Exception as exc:
            return NotifyResult(
                delivered=False,
                detail=f"{type(exc).__name__}: {exc}",
                latency_ms=_elapsed_ms(started),
            )
        latency = _elapsed_ms(started)
        # Teams returns 200 with body "1" on success.
        if resp.status_code == 200 and resp.text.strip() == "1":
            return NotifyResult(
                delivered=True,
                detail="ok",
                latency_ms=latency,
            )
        return NotifyResult(
            delivered=False,
            detail=f"http {resp.status_code}: {resp.text[:200]}",
            latency_ms=latency,
        )

    async def health_check(self) -> HealthStatus:
        started = time.monotonic()
        try:
            url = self._get_webhook()
        except NotifierError as exc:
            return HealthStatus(
                ok=False,
                latency_ms=_elapsed_ms(started),
                detail=str(exc),
                last_checked=datetime.now(UTC),
            )
        probe = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": _SEVERITY_THEME["info"],
            "title": "secops-term health probe",
            "text": "If you see this, ignore — automated reachability check.",
        }
        try:
            async with HardenedClient() as http:
                resp = await http.post(url, json=probe)
        except Exception as exc:
            return HealthStatus(
                ok=False,
                latency_ms=_elapsed_ms(started),
                detail=f"{type(exc).__name__}: {exc}",
                last_checked=datetime.now(UTC),
            )
        latency = _elapsed_ms(started)
        if resp.status_code == 200 and resp.text.strip() == "1":
            return HealthStatus(
                ok=True,
                latency_ms=latency,
                detail="ok",
                last_checked=datetime.now(UTC),
            )
        return HealthStatus(
            ok=False,
            latency_ms=latency,
            detail=f"http {resp.status_code}: {resp.text[:120]}",
            last_checked=datetime.now(UTC),
        )

    # Internals

    def _get_webhook(self) -> str:
        try:
            mgr = secrets_mod.get_manager()
        except Exception as exc:
            raise NotifierError(
                f"teams:{self.instance}: no secrets manager available: {exc}"
            ) from exc
        url = mgr.get_secret(_KEYRING_PROVIDER, self.instance, _WEBHOOK_FIELD)
        if not url:
            raise NotifierError(
                f"teams:{self.instance}: no webhook URL in keyring "
                f"(`{_KEYRING_PROVIDER}:{self.instance}/{_WEBHOOK_FIELD}`)"
            )
        return url

    def _render(self, payload: NotifyPayload) -> dict[str, Any]:
        theme = _SEVERITY_THEME.get(payload.severity, "808080")
        card: dict[str, Any] = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": theme,
            "title": payload.summary,
            "text": payload.body,
        }
        if payload.context:
            sections = [
                {
                    "facts": [
                        {"name": str(k), "value": _short(str(v))}
                        for k, v in list(payload.context.items())[:8]
                    ]
                }
            ]
            card["sections"] = sections
        return card


def _short(s: str) -> str:
    return s if len(s) <= 200 else s[:197] + "..."


def _elapsed_ms(started: float) -> float:
    return (time.monotonic() - started) * 1000.0


__all__ = ["TeamsNotifier"]
