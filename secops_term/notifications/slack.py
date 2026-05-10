"""Slack Incoming-Webhook notifier.

Per brief v3 §6.6: webhook URL is treated as a credential and lives in
the keyring (``secops-term:notifications.slack:<instance>`` /
``webhook_url``). The config-toml block carries no URL, only the
instance name. SSRF-guarded via :class:`HardenedClient`.

Severity → Slack color:

- ``info``  → ``"#36a64f"`` (green)
- ``warn``  → ``"#ff9933"`` (orange)
- ``error`` → ``"#cc0000"`` (red)
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

_KEYRING_PROVIDER = "notifications.slack"
_WEBHOOK_FIELD = "webhook_url"

_SEVERITY_COLOR: dict[str, str] = {
    "info": "#36a64f",
    "warn": "#ff9933",
    "error": "#cc0000",
}


@NOTIFIERS.register("slack")
class SlackNotifier:
    """Slack Incoming-Webhook notifier."""

    name: ClassVar[str] = "slack"

    def __init__(self, instance: str) -> None:
        self.instance = instance

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> SlackNotifier:
        # Slack has no per-instance config in TOML — webhook URL is the
        # only knob and it lives in the keyring. We accept (and ignore)
        # any extra keys so future additions don't break existing configs.
        if "url" in cfg or "webhook_url" in cfg:
            raise NotifierError(
                f"slack:{instance}: webhook URLs are credentials and must live in the "
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
        # Slack returns 200 with body "ok" on success; any other 2xx
        # treated as success too. Slack-specific 4xx like "invalid_payload"
        # come back as 200 + body!= "ok" — fail those.
        if resp.status_code == 200 and resp.text.strip() == "ok":
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
        """Slack doesn't expose an auth-validating endpoint that doesn't
        post to the channel, so we send a low-noise probe message. The
        default 'ok' response confirms reachability + auth simultaneously.
        """
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
            "text": "secops-term health probe (automated; safe to ignore)",
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
        if resp.status_code == 200 and resp.text.strip() == "ok":
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
                f"slack:{self.instance}: no secrets manager available: {exc}"
            ) from exc
        url = mgr.get_secret(_KEYRING_PROVIDER, self.instance, _WEBHOOK_FIELD)
        if not url:
            raise NotifierError(
                f"slack:{self.instance}: no webhook URL in keyring "
                f"(`{_KEYRING_PROVIDER}:{self.instance}/{_WEBHOOK_FIELD}`)"
            )
        return url

    def _render(self, payload: NotifyPayload) -> dict[str, Any]:
        color = _SEVERITY_COLOR.get(payload.severity, "#cccccc")
        # Slack legacy attachment format — works on both Incoming Webhooks
        # and most chatops bots that accept them.
        attachment: dict[str, Any] = {
            "color": color,
            "title": payload.summary,
            "text": payload.body,
            "fallback": f"{payload.summary}: {payload.body[:200]}",
            "footer": "secops-terminal",
        }
        if payload.context:
            fields = [
                {"title": str(k), "value": _short(str(v)), "short": True}
                for k, v in list(payload.context.items())[:8]
            ]
            attachment["fields"] = fields
        return {"attachments": [attachment]}


def _short(s: str) -> str:
    return s if len(s) <= 200 else s[:197] + "..."


def _elapsed_ms(started: float) -> float:
    return (time.monotonic() - started) * 1000.0


__all__ = ["SlackNotifier"]
