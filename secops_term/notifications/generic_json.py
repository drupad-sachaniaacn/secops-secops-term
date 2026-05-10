"""Generic-JSON notifier — POSTs a JSON envelope to a configured URL.

Per brief v3 §6.6:

- URL stored in ``config.toml`` by default; user may opt-in to keyring
  for the URL itself (e.g. when it embeds an auth segment).
- Optional bearer token in keyring (``secops-term:notifications.generic_json:<instance>``,
  field ``bearer_token``).
- SSRF-guarded via :mod:`secops_term.core.url_guard`.
- JSON template choice: ``standard`` (default) or ``compact``.

Multi-instance: ``[notifications.generic_json."internal-bot"]`` etc. The
playbook references it as ``generic_json:internal-bot``.
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

_KEYRING_PROVIDER_PREFIX = "notifications.generic_json"
_BEARER_FIELD = "bearer_token"
_URL_FIELD = "url"  # only when user opted-in to keyring storage for URL

_KNOWN_TEMPLATES = ("standard", "compact")


@NOTIFIERS.register("generic_json")
class GenericJsonNotifier:
    """JSON-payload webhook notifier."""

    name: ClassVar[str] = "generic_json"

    def __init__(
        self,
        instance: str,
        *,
        url: str | None,
        template: str = "standard",
    ) -> None:
        if template not in _KNOWN_TEMPLATES:
            raise NotifierError(
                f"generic_json:{instance}: template must be one of "
                f"{list(_KNOWN_TEMPLATES)}, got {template!r}"
            )
        self.instance = instance
        self._url = url
        self._template = template

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> GenericJsonNotifier:
        raw_url = cfg.get("url")
        if raw_url is not None and not isinstance(raw_url, str):
            raise NotifierError(
                f"generic_json:{instance}: url must be a string, got {type(raw_url).__name__}"
            )
        template = cfg.get("template", "standard")
        if not isinstance(template, str):
            raise NotifierError(f"generic_json:{instance}: template must be a string")
        return cls(instance, url=raw_url, template=template)

    @property
    def template(self) -> str:
        return self._template

    # Public API

    async def send(self, payload: NotifyPayload) -> NotifyResult:
        started = time.monotonic()
        try:
            url = self._resolve_url()
        except NotifierError as exc:
            return NotifyResult(
                delivered=False,
                detail=str(exc),
                latency_ms=_elapsed_ms(started),
            )
        body = self._render(payload)
        headers = {"Content-Type": "application/json"}
        bearer = self._get_bearer()
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"
        try:
            async with HardenedClient() as http:
                resp = await http.post(url, headers=headers, json=body)
        except Exception as exc:
            return NotifyResult(
                delivered=False,
                detail=f"{type(exc).__name__}: {exc}",
                latency_ms=_elapsed_ms(started),
            )
        latency = _elapsed_ms(started)
        if 200 <= resp.status_code < 300:
            return NotifyResult(
                delivered=True, detail=f"http {resp.status_code}", latency_ms=latency
            )
        return NotifyResult(
            delivered=False,
            detail=f"http {resp.status_code}: {resp.text[:200]}",
            latency_ms=latency,
        )

    async def health_check(self) -> HealthStatus:
        """Probe the URL with the same payload shape used for real sends.

        We send a small dry-run payload (severity=info, summary="ping") and
        accept any 2xx as healthy. Some webhooks reject empty / oddly-shaped
        bodies, so we always send a real-looking payload.
        """
        started = time.monotonic()
        try:
            url = self._resolve_url()
        except NotifierError as exc:
            return HealthStatus(
                ok=False,
                latency_ms=_elapsed_ms(started),
                detail=str(exc),
                last_checked=datetime.now(UTC),
            )
        probe_body = self._render(
            NotifyPayload(
                summary="secops-term health probe",
                body="If you see this, ignore — automated reachability check.",
                severity="info",
                context={},
            )
        )
        headers = {"Content-Type": "application/json"}
        bearer = self._get_bearer()
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"
        try:
            async with HardenedClient() as http:
                resp = await http.post(url, headers=headers, json=probe_body)
        except Exception as exc:
            return HealthStatus(
                ok=False,
                latency_ms=_elapsed_ms(started),
                detail=f"{type(exc).__name__}: {exc}",
                last_checked=datetime.now(UTC),
            )
        latency = _elapsed_ms(started)
        if 200 <= resp.status_code < 300:
            return HealthStatus(
                ok=True,
                latency_ms=latency,
                detail=f"http {resp.status_code}",
                last_checked=datetime.now(UTC),
            )
        return HealthStatus(
            ok=False,
            latency_ms=latency,
            detail=f"http {resp.status_code}",
            last_checked=datetime.now(UTC),
        )

    # Internals

    def _resolve_url(self) -> str:
        """URL precedence: constructor → keyring → error."""
        if self._url:
            return self._url
        keyring_url = self._get_secret(_URL_FIELD)
        if keyring_url:
            return keyring_url
        raise NotifierError(
            f"generic_json:{self.instance}: no url configured "
            f"(set in config.toml or in keyring under "
            f"`{_KEYRING_PROVIDER_PREFIX}:{self.instance}/{_URL_FIELD}`)"
        )

    def _get_bearer(self) -> str | None:
        return self._get_secret(_BEARER_FIELD)

    def _get_secret(self, field: str) -> str | None:
        try:
            mgr = secrets_mod.get_manager()
        except Exception:
            return None
        try:
            return mgr.get_secret(_KEYRING_PROVIDER_PREFIX, self.instance, field)
        except Exception:
            return None

    def _render(self, payload: NotifyPayload) -> dict[str, Any]:
        if self._template == "compact":
            return {
                "summary": payload.summary,
                "severity": payload.severity,
                "body": payload.body,
            }
        # standard
        return {
            "source": "secops-terminal",
            "instance": self.instance,
            "summary": payload.summary,
            "severity": payload.severity,
            "body": payload.body,
            "context": dict(payload.context),
        }


def _elapsed_ms(started: float) -> float:
    return (time.monotonic() - started) * 1000.0


__all__ = ["GenericJsonNotifier"]
