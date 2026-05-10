"""Trend Micro Vision One (XDR) client — Search + Workbench + health probe.

Per brief v3 §13: region is **locked to US** — base URL hardcoded to
``https://api.xdr.trendmicro.com``. Tests / private deployments can override
via :class:`VisionOneConfig.base_url` but the wizard never asks for it.

Authentication is a static bearer token (per-tenant API key from the V1
console). The token lives in the keyring under
``secops-term:vision_one:<instance>`` / ``api_token`` (per §3.5.13). No
OAuth refresh dance — much simpler than Chronicle.

Endpoints used in Phase 3.1:

- ``GET /v3.0/iam/account`` — health probe (auth-validating, low cost).
- ``POST /v3.0/search/endpointActivities`` — TMV1-query retro hunt.
- ``GET /v3.0/workbench/alerts`` — alert list (used by the Phase 3.3 ingest).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from secops_term.core.health import HealthStatus
from secops_term.core.http import HardenedClient, HTTPConfig

# Locked per brief §13 (Vision One US region).
VISION_ONE_BASE_URL = "https://api.xdr.trendmicro.com"


class VisionOneError(Exception):
    """Base class for Vision One client errors."""


class VisionOneAPIError(VisionOneError):
    """The Vision One API returned a non-success status."""

    def __init__(self, status_code: int, body: str) -> None:
        super().__init__(f"Vision One API HTTP {status_code}: {body[:500]}")
        self.status_code = status_code
        self.body = body


@dataclass(frozen=True)
class VisionOneConfig:
    """Static config for one Vision One tenant.

    ``api_token`` is the bearer token (kept in this dataclass because the
    client needs it on every request). Production code constructs this via
    :func:`secops_term.trendmicro.factory.build_vision_one_client`, which
    pulls the token from the keyring; tests construct directly with a
    fake token.
    """

    api_token: str
    base_url: str = VISION_ONE_BASE_URL
    allow_write: bool = False

    def resolved_base_url(self) -> str:
        return self.base_url.rstrip("/")


@dataclass(frozen=True)
class V1SearchResult:
    """Result of one ``search_activities`` call."""

    activities: list[dict[str, Any]] = field(default_factory=list)
    next_link: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class V1WorkbenchAlertsResult:
    """Result of one ``list_workbench_alerts`` call."""

    alerts: list[dict[str, Any]] = field(default_factory=list)
    total_count: int | None = None
    next_link: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class VisionOneClient:
    """Vision One XDR client."""

    name = "vision_one"

    def __init__(self, cfg: VisionOneConfig) -> None:
        if not cfg.api_token:
            raise VisionOneError("VisionOneConfig.api_token must be non-empty")
        self._cfg = cfg
        self._base_url = cfg.resolved_base_url()

    @property
    def cfg(self) -> VisionOneConfig:
        return self._cfg

    @property
    def base_url(self) -> str:
        return self._base_url

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._cfg.api_token}",
            "Content-Type": "application/json",
        }

    async def health_check(self) -> HealthStatus:
        """Auth-validating probe via ``/v3.0/iam/account``."""
        started = time.monotonic()
        try:
            async with HardenedClient() as http:
                resp = await http.get(
                    f"{self._base_url}/v3.0/iam/account",
                    headers=self._headers(),
                )
        except Exception as exc:
            return _failed(f"{type(exc).__name__}: {exc}", started)
        latency_ms = (time.monotonic() - started) * 1000
        if resp.status_code in (401, 403):
            return _failed(f"auth rejected (HTTP {resp.status_code})", started)
        if resp.status_code != 200:
            return _failed(f"HTTP {resp.status_code}", started)
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        identity = ""
        if isinstance(payload, dict):
            for key in ("email", "loginAccount", "userName"):
                v = payload.get(key)
                if isinstance(v, str) and v:
                    identity = v
                    break
        return HealthStatus(
            ok=True,
            latency_ms=latency_ms,
            detail=f"auth ok ({identity})" if identity else "auth ok",
            last_checked=datetime.now(UTC),
        )

    async def search_activities(
        self,
        query: str,
        *,
        lookback_hours: int = 30 * 24,
        limit: int = 1000,
        end_time: datetime | None = None,
    ) -> V1SearchResult:
        """Run a TMV1 endpoint-activity search.

        ``query`` is a TMV1 query expression (built per-IOC-type by the
        retro-hunt query builder in Phase 3.3). The time range is computed
        from ``lookback_hours`` (default 30 days, per brief §6.2).
        """
        if not query.strip():
            raise VisionOneError("query is empty")
        if limit < 1 or limit > 5000:
            raise VisionOneError(f"limit must be in [1, 5000], got {limit}")
        if lookback_hours < 1:
            raise VisionOneError(f"lookback_hours must be >= 1, got {lookback_hours}")
        end_dt = end_time if end_time is not None else datetime.now(UTC)
        start_dt = end_dt - timedelta(hours=lookback_hours)

        params = {
            "startDateTime": _iso(start_dt),
            "endDateTime": _iso(end_dt),
            "top": str(limit),
        }
        body = {"query": query}
        async with HardenedClient(HTTPConfig(response_cap_bytes=50 * 1024 * 1024)) as http:
            resp = await http.post(
                f"{self._base_url}/v3.0/search/endpointActivities",
                headers=self._headers(),
                params=params,
                json=body,
            )
        if resp.status_code != 200:
            raise VisionOneAPIError(resp.status_code, resp.text)
        try:
            payload = resp.json()
        except Exception as exc:
            raise VisionOneError(f"V1 response was not JSON: {exc}") from exc
        return _parse_search_response(payload)

    async def list_workbench_alerts(
        self,
        *,
        since: datetime | None = None,
        statuses: tuple[str, ...] = ("Open", "InProgress"),
        limit: int = 100,
    ) -> V1WorkbenchAlertsResult:
        """List Workbench alerts, optionally filtered by ``investigationStatus``.

        Defaults to "Open" + "InProgress" per brief §6.3 (open + investigating).
        ``since`` becomes the ``startDateTime`` query parameter when set.
        """
        if limit < 1 or limit > 1000:
            raise VisionOneError(f"limit must be in [1, 1000], got {limit}")
        params: dict[str, str] = {"top": str(limit)}
        if since is not None:
            params["startDateTime"] = _iso(since)
        if statuses:
            clauses = [f"investigationStatus eq '{s}'" for s in statuses]
            params["$filter"] = "(" + " or ".join(clauses) + ")"
        async with HardenedClient() as http:
            resp = await http.get(
                f"{self._base_url}/v3.0/workbench/alerts",
                headers=self._headers(),
                params=params,
            )
        if resp.status_code != 200:
            raise VisionOneAPIError(resp.status_code, resp.text)
        try:
            payload = resp.json()
        except Exception as exc:
            raise VisionOneError(f"V1 response was not JSON: {exc}") from exc
        return _parse_workbench_response(payload)


def _parse_search_response(payload: Any) -> V1SearchResult:
    if not isinstance(payload, dict):
        return V1SearchResult()
    items = payload.get("items")
    activities = [a for a in items if isinstance(a, dict)] if isinstance(items, list) else []
    next_link = payload.get("nextLink")
    return V1SearchResult(
        activities=activities,
        next_link=next_link if isinstance(next_link, str) else None,
        raw=payload,
    )


def _parse_workbench_response(payload: Any) -> V1WorkbenchAlertsResult:
    if not isinstance(payload, dict):
        return V1WorkbenchAlertsResult()
    items = payload.get("items")
    alerts = [a for a in items if isinstance(a, dict)] if isinstance(items, list) else []
    total = payload.get("totalCount")
    next_link = payload.get("nextLink")
    return V1WorkbenchAlertsResult(
        alerts=alerts,
        total_count=int(total) if isinstance(total, int) else None,
        next_link=next_link if isinstance(next_link, str) else None,
        raw=payload,
    )


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _failed(detail: str, started: float) -> HealthStatus:
    return HealthStatus(
        ok=False,
        latency_ms=(time.monotonic() - started) * 1000,
        detail=detail,
        last_checked=datetime.now(UTC),
    )


__all__ = [
    "VISION_ONE_BASE_URL",
    "V1SearchResult",
    "V1WorkbenchAlertsResult",
    "VisionOneAPIError",
    "VisionOneClient",
    "VisionOneConfig",
    "VisionOneError",
]
