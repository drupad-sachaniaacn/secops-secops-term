"""AlienVault OTX threat-intel provider.

Per brief v3 §6.1: subscribed pulses + author follows. Auth via the
``X-OTX-API-KEY`` header; the token lives in the keyring under
``secops-term:intel.otx:<instance>`` / ``api_token``.

Health check: ``GET /users/me`` — quota-free.

OTX indicator types map onto our schema:

- ``IPv4`` → ``ipv4``
- ``IPv6`` → ``ipv6``
- ``domain`` / ``hostname`` → ``domain``
- ``URL`` → ``url``
- ``FileHash-MD5`` → ``md5``
- ``FileHash-SHA1`` → ``sha1``
- ``FileHash-SHA256`` → ``sha256``
- ``email`` → ``email``
- ``CVE`` → ``cve``

Anything else is silently dropped.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, ClassVar

from secops_term.core import secrets as secrets_mod
from secops_term.core.health import HealthStatus
from secops_term.core.http import HardenedClient
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers.base import IntelProviderError, IntelRecord

_BASE_URL = "https://otx.alienvault.com/api/v1"
_KEYRING_PROVIDER = "intel.otx"
_KEYRING_FIELD = "api_token"

_TYPE_MAP: dict[str, str] = {
    "IPv4": "ipv4",
    "IPv6": "ipv6",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
    "FileHash-SHA256": "sha256",
    "email": "email",
    "CVE": "cve",
}


@PROVIDERS.register("otx")
class OTXProvider:
    """AlienVault OTX intel provider — pulls subscribed pulses."""

    name: ClassVar[str] = "otx"

    def __init__(self, instance: str) -> None:
        self.instance = instance

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> OTXProvider:
        # OTX takes no provider-specific config in Phase 1; the API key is
        # the only setting and lives in the keyring.
        del cfg
        return cls(instance)

    async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
        token = self._get_token()
        params: dict[str, str] = {}
        if since is not None:
            params["modified_since"] = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S")
        async with HardenedClient() as http:
            resp = await http.get(
                f"{_BASE_URL}/pulses/subscribed",
                params=params,
                headers={"X-OTX-API-KEY": token},
            )
        if resp.status_code != 200:
            return []
        try:
            payload = resp.json()
        except Exception:
            return []
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list):
            return []
        fetched_at = datetime.now(UTC)
        records: list[IntelRecord] = []
        for pulse in results:
            if not isinstance(pulse, dict):
                continue
            pulse_id = str(pulse.get("id") or "")
            pulse_name = str(pulse.get("name") or "")
            tags_raw = pulse.get("tags") or []
            tags = tuple(str(t) for t in tags_raw if isinstance(t, str))
            indicators = pulse.get("indicators") or []
            if not isinstance(indicators, list):
                continue
            for ind in indicators:
                if not isinstance(ind, dict):
                    continue
                otx_type = ind.get("type")
                value = ind.get("indicator")
                our_type = _TYPE_MAP.get(str(otx_type)) if otx_type else None
                if our_type is None or not isinstance(value, str) or not value:
                    continue
                records.append(
                    IntelRecord(
                        source=f"otx:{self.instance}",
                        type=our_type,
                        value=value,
                        fetched_at=fetched_at,
                        context=pulse_name[:200] or None,
                        source_ref=pulse_id or None,
                        tags=tags,
                    )
                )
        return records

    async def health_check(self) -> HealthStatus:
        """``GET /users/me`` — quota-free OTX auth probe."""
        started = time.monotonic()
        try:
            token = self._get_token()
        except IntelProviderError as exc:
            return _failed(f"{exc}", started)
        try:
            async with HardenedClient() as http:
                resp = await http.get(
                    f"{_BASE_URL}/users/me",
                    headers={"X-OTX-API-KEY": token},
                )
        except Exception as exc:
            return _failed(f"{type(exc).__name__}: {exc}", started)
        latency_ms = (time.monotonic() - started) * 1000
        if resp.status_code == 401 or resp.status_code == 403:
            return _failed(f"auth rejected (HTTP {resp.status_code})", started)
        if resp.status_code != 200:
            return _failed(f"HTTP {resp.status_code}", started)
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        username = payload.get("username") if isinstance(payload, dict) else None
        return HealthStatus(
            ok=True,
            latency_ms=latency_ms,
            detail=f"auth ok (user={username!r})" if username else "auth ok",
            last_checked=datetime.now(UTC),
        )

    def _get_token(self) -> str:
        mgr = secrets_mod.get_manager()
        token = mgr.get_secret(_KEYRING_PROVIDER, self.instance, _KEYRING_FIELD)
        if not token:
            raise IntelProviderError(
                f"{self.name}:{self.instance}: no api_token configured "
                f"(run `secops-term config intel otx --instance {self.instance}`)"
            )
        return token


def _failed(detail: str, started: float) -> HealthStatus:
    return HealthStatus(
        ok=False,
        latency_ms=(time.monotonic() - started) * 1000,
        detail=detail,
        last_checked=datetime.now(UTC),
    )


# Re-export for type-checkers that want to silence "imported but unused".
_ = json
