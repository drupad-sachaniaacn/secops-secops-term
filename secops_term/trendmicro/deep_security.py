"""Trend Micro Deep Security read-only client.

Per brief v3 §13: scope is **locked read-only in v1** — alerts list +
agent (computer) status only. No policy reads, no writes. The same client
serves DSaaS (Trend-hosted) and on-prem deployments; only the base URL
differs.

Authentication:

- ``api-secret-key: <key>`` header (DS convention — *not* Bearer).
- ``api-version: v1`` header is required by the DS API.

The API key lives in the keyring under
``secops-term:deep_security:<instance>`` / ``api_key`` (per brief §3.5.13).

Endpoints used in Phase 3.2:

- ``GET /api/computers`` — list agents (used by ``list_agents`` and the
  health probe).
- ``GET /api/alerts`` — list alerts (used by ``list_alerts`` and the
  Phase 3.3 unified-alert ingest).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from secops_term.core.health import HealthStatus
from secops_term.core.http import HardenedClient

# Default DSaaS endpoint; on-prem overrides via base_url.
DSAAS_BASE_URL = "https://app.deepsecurity.trendmicro.com"

DeploymentType = Literal["dsaas", "on_prem"]
_KNOWN_DEPLOYMENT_TYPES: tuple[DeploymentType, ...] = ("dsaas", "on_prem")


class DeepSecurityError(Exception):
    """Base class for Deep Security errors."""


class DeepSecurityAPIError(DeepSecurityError):
    """The Deep Security API returned a non-success status."""

    def __init__(self, status_code: int, body: str) -> None:
        super().__init__(f"Deep Security API HTTP {status_code}: {body[:500]}")
        self.status_code = status_code
        self.body = body


@dataclass(frozen=True)
class DeepSecurityConfig:
    """Static config for one Deep Security tenant.

    Notably absent: ``allow_write``. Phase 3.2 scope is locked read-only
    per brief §13; the toggle would be misleading. Phase 6+ may add it
    when policy-write surface lands.
    """

    api_key: str
    base_url: str
    deployment_type: DeploymentType = "dsaas"

    def resolved_base_url(self) -> str:
        return self.base_url.rstrip("/")


@dataclass(frozen=True)
class DSAgentsResult:
    """Result of one ``list_agents`` call."""

    agents: list[dict[str, Any]] = field(default_factory=list)
    total: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DSAlertsResult:
    """Result of one ``list_alerts`` call."""

    alerts: list[dict[str, Any]] = field(default_factory=list)
    total: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class DeepSecurityClient:
    """Deep Security (DSaaS / on-prem) read-only client."""

    name = "deep_security"

    def __init__(self, cfg: DeepSecurityConfig) -> None:
        if not cfg.api_key:
            raise DeepSecurityError("DeepSecurityConfig.api_key must be non-empty")
        if not cfg.base_url:
            raise DeepSecurityError("DeepSecurityConfig.base_url must be non-empty")
        if cfg.deployment_type not in _KNOWN_DEPLOYMENT_TYPES:
            raise DeepSecurityError(
                f"unknown deployment_type: {cfg.deployment_type!r}; "
                f"valid: {list(_KNOWN_DEPLOYMENT_TYPES)}"
            )
        self._cfg = cfg
        self._base_url = cfg.resolved_base_url()

    @property
    def cfg(self) -> DeepSecurityConfig:
        return self._cfg

    @property
    def base_url(self) -> str:
        return self._base_url

    def _headers(self) -> dict[str, str]:
        return {
            "api-secret-key": self._cfg.api_key,
            "api-version": "v1",
            "Content-Type": "application/json",
        }

    async def health_check(self) -> HealthStatus:
        """Auth-validating probe: list one computer.

        Cheapest call that actually exercises auth + base URL + a real
        endpoint. Returns 0-1 results regardless of the customer's fleet.
        """
        started = time.monotonic()
        try:
            async with HardenedClient() as http:
                resp = await http.get(
                    f"{self._base_url}/api/computers",
                    headers=self._headers(),
                    params={"limit": "1"},
                )
        except Exception as exc:
            return _failed(f"{type(exc).__name__}: {exc}", started)
        latency_ms = (time.monotonic() - started) * 1000
        if resp.status_code in (401, 403):
            return _failed(f"auth rejected (HTTP {resp.status_code})", started)
        if resp.status_code != 200:
            return _failed(f"HTTP {resp.status_code}", started)
        # We don't actually need to parse the body — the 200 alone proves
        # auth + base URL + endpoint are good. Surfacing the deployment
        # type in the detail line lets the user spot DSaaS-vs-on-prem
        # config mix-ups at a glance.
        return HealthStatus(
            ok=True,
            latency_ms=latency_ms,
            detail=f"auth ok ({self._cfg.deployment_type})",
            last_checked=datetime.now(UTC),
        )

    async def list_agents(self, *, limit: int = 100) -> DSAgentsResult:
        """List computers / agents. Read-only."""
        if limit < 1 or limit > 5000:
            raise DeepSecurityError(f"limit must be in [1, 5000], got {limit}")
        async with HardenedClient() as http:
            resp = await http.get(
                f"{self._base_url}/api/computers",
                headers=self._headers(),
                params={"limit": str(limit)},
            )
        if resp.status_code != 200:
            raise DeepSecurityAPIError(resp.status_code, resp.text)
        try:
            payload = resp.json()
        except Exception as exc:
            raise DeepSecurityError(f"DS response was not JSON: {exc}") from exc
        return _parse_agents_response(payload)

    async def list_alerts(
        self,
        *,
        since: datetime | None = None,
        limit: int = 100,
    ) -> DSAlertsResult:
        """List active alerts. Read-only."""
        if limit < 1 or limit > 5000:
            raise DeepSecurityError(f"limit must be in [1, 5000], got {limit}")
        params: dict[str, str] = {"limit": str(limit)}
        if since is not None:
            params["since"] = _iso(since)
        async with HardenedClient() as http:
            resp = await http.get(
                f"{self._base_url}/api/alerts",
                headers=self._headers(),
                params=params,
            )
        if resp.status_code != 200:
            raise DeepSecurityAPIError(resp.status_code, resp.text)
        try:
            payload = resp.json()
        except Exception as exc:
            raise DeepSecurityError(f"DS response was not JSON: {exc}") from exc
        return _parse_alerts_response(payload)


def _parse_agents_response(payload: Any) -> DSAgentsResult:
    if not isinstance(payload, dict):
        return DSAgentsResult()
    raw_agents = payload.get("computers")
    if not isinstance(raw_agents, list):
        raw_agents = []
    agents = [a for a in raw_agents if isinstance(a, dict)]
    total = payload.get("totalCount") or payload.get("total")
    return DSAgentsResult(
        agents=agents,
        total=int(total) if isinstance(total, int) else None,
        raw=payload,
    )


def _parse_alerts_response(payload: Any) -> DSAlertsResult:
    if not isinstance(payload, dict):
        return DSAlertsResult()
    raw_alerts = payload.get("alerts")
    if not isinstance(raw_alerts, list):
        raw_alerts = []
    alerts = [a for a in raw_alerts if isinstance(a, dict)]
    total = payload.get("totalCount") or payload.get("total")
    return DSAlertsResult(
        alerts=alerts,
        total=int(total) if isinstance(total, int) else None,
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
    "DSAAS_BASE_URL",
    "DSAgentsResult",
    "DSAlertsResult",
    "DeepSecurityAPIError",
    "DeepSecurityClient",
    "DeepSecurityConfig",
    "DeepSecurityError",
    "DeploymentType",
]
