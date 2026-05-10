"""GreyNoise threat-intel provider.

Per brief v3 §6.1. Queries the GreyNoise GNQL (GreyNoise Query Language) API
to pull malicious/scanning IP addresses. Enterprise/Research keys have full
GNQL access; Community keys receive an empty list from ``pull()`` — health-
check still validates auth via the lightweight ``/ping`` endpoint.

Auth: ``key`` header; keyring ``secops-term:intel.greynoise:<instance>``
/ ``api_key``.

Health check: ``GET /ping`` — auth-validating, zero-quota cost.

Config:

.. code-block:: toml

    [intel_providers.greynoise.default]
    enabled = true
    query = "classification:malicious"  # GNQL query (default)
    limit = 100                         # max results per pull (1-1000)

IOC types produced: ``ipv4`` only (GreyNoise exclusively tracks IP addresses).
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, ClassVar

from secops_term.core import secrets as secrets_mod
from secops_term.core.health import HealthStatus
from secops_term.core.http import HardenedClient
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers.base import IntelProviderError, IntelRecord

_BASE_URL = "https://api.greynoise.io"
_KEYRING_PROVIDER = "intel.greynoise"
_KEYRING_FIELD = "api_key"
_DEFAULT_QUERY = "classification:malicious"
_DEFAULT_LIMIT = 100


@PROVIDERS.register("greynoise")
class GreyNoiseProvider:
    """GreyNoise intel provider — pulls malicious/scanning IPs via GNQL."""

    name: ClassVar[str] = "greynoise"

    def __init__(
        self,
        instance: str,
        *,
        query: str = _DEFAULT_QUERY,
        limit: int = _DEFAULT_LIMIT,
    ) -> None:
        self.instance = instance
        self._query = query
        self._limit = max(1, min(1000, limit))

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> GreyNoiseProvider:
        query = str(cfg.get("query") or _DEFAULT_QUERY)
        raw_limit = cfg.get("limit", _DEFAULT_LIMIT)
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            limit = _DEFAULT_LIMIT
        return cls(instance, query=query, limit=limit)

    async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
        """Pull malicious IP records from the GreyNoise GNQL API.

        Returns an empty list for Community keys (HTTP 401/403 from the GNQL
        endpoint) without raising — operators should expect this.
        """
        token = self._get_token()
        params: dict[str, str | int] = {
            "query": self._query,
            "size": self._limit,
        }
        try:
            async with HardenedClient() as http:
                resp = await http.get(
                    f"{_BASE_URL}/v2/experimental/gnql",
                    params=params,
                    headers={"key": token},
                )
        except Exception:
            return []
        if resp.status_code in (401, 403):
            # Community key — no GNQL access; degrade gracefully.
            return []
        if resp.status_code != 200:
            return []
        try:
            payload = resp.json()
        except Exception:
            return []
        if not isinstance(payload, dict):
            return []
        data = payload.get("data")
        if not isinstance(data, list):
            return []
        fetched_at = datetime.now(UTC)
        records: list[IntelRecord] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip")
            if not isinstance(ip, str) or not ip:
                continue
            # Filter by last_seen when `since` is supplied.
            # GN returns `last_seen` as "YYYY-MM-DD" or "YYYY-MM-DDTHH:MM:SSZ".
            if since is not None:
                last_seen_raw = entry.get("last_seen")
                if isinstance(last_seen_raw, str):
                    try:
                        if "T" in last_seen_raw:
                            ls_dt = datetime.fromisoformat(last_seen_raw.replace("Z", "+00:00"))
                        else:
                            ls_dt = datetime.strptime(last_seen_raw, "%Y-%m-%d").replace(tzinfo=UTC)
                        if ls_dt < since:
                            continue
                    except (ValueError, TypeError):
                        pass
            classification = str(entry.get("classification") or "")
            malware_name = str(entry.get("name") or "")
            tags_raw = entry.get("tags") or []
            tags = tuple(str(t) for t in tags_raw if isinstance(t, str))
            ctx_parts = [p for p in (classification, malware_name) if p]
            ctx: str | None = " / ".join(ctx_parts)[:200] or None
            records.append(
                IntelRecord(
                    source=f"greynoise:{self.instance}",
                    type="ipv4",
                    value=ip,
                    fetched_at=fetched_at,
                    context=ctx,
                    source_ref=None,
                    tags=tags,
                )
            )
        return records

    async def health_check(self) -> HealthStatus:
        """``GET /ping`` — auth-validating, zero-quota cost."""
        started = time.monotonic()
        try:
            token = self._get_token()
        except IntelProviderError as exc:
            return _failed(str(exc), started)
        try:
            async with HardenedClient() as http:
                resp = await http.get(
                    f"{_BASE_URL}/ping",
                    headers={"key": token},
                )
        except Exception as exc:
            return _failed(f"{type(exc).__name__}: {exc}", started)
        latency_ms = (time.monotonic() - started) * 1000
        if resp.status_code in (401, 403):
            return _failed(f"auth rejected (HTTP {resp.status_code})", started)
        if resp.status_code != 200:
            return _failed(f"HTTP {resp.status_code}", started)
        try:
            body = resp.json()
        except Exception:
            body = {}
        offering = body.get("offering") if isinstance(body, dict) else None
        detail = f"auth ok (offering={offering!r})" if offering else "auth ok"
        return HealthStatus(
            ok=True,
            latency_ms=latency_ms,
            detail=detail,
            last_checked=datetime.now(UTC),
        )

    def _get_token(self) -> str:
        mgr = secrets_mod.get_manager()
        token = mgr.get_secret(_KEYRING_PROVIDER, self.instance, _KEYRING_FIELD)
        if not token:
            raise IntelProviderError(
                f"{self.name}:{self.instance}: no api_key configured "
                f"(run `secops-term config intel greynoise --instance {self.instance}`)"
            )
        return token


def _failed(detail: str, started: float) -> HealthStatus:
    return HealthStatus(
        ok=False,
        latency_ms=(time.monotonic() - started) * 1000,
        detail=detail,
        last_checked=datetime.now(UTC),
    )


__all__ = ["GreyNoiseProvider"]
