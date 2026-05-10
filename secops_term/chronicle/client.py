"""Chronicle SecOps API client — UDM Search + health check.

Per brief v3 §6.2: this is the **ad-hoc retro-hunt** client. We hit Chronicle's
UDM Search endpoint with a generated filter expression (see
:mod:`secops_term.chronicle.retro_hunt`, Phase 2.2) and parse out the
matching events. **Not** the Rules Engine; **not** YARA-L deployment.

Region → base-URL mapping covers the documented Chronicle SecOps regions.
Callers can also pass an explicit ``base_url=`` to point at a private
deployment or future-region URL.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from secops_term.chronicle.auth import ChronicleAuth, ChronicleAuthError
from secops_term.core.health import HealthStatus
from secops_term.core.http import HardenedClient, HTTPConfig

# Documented Chronicle SecOps regions. Override via `base_url=` if your
# tenant uses a region we haven't mapped yet.
REGION_BASE_URLS: dict[str, str] = {
    "us": "https://us-chronicle.googleapis.com",
    "europe": "https://europe-chronicle.googleapis.com",
    "europe-west2": "https://europe-west2-chronicle.googleapis.com",
    "europe-west3": "https://europe-west3-chronicle.googleapis.com",
    "asia-southeast1": "https://asia-southeast1-chronicle.googleapis.com",
    "asia-northeast1": "https://asia-northeast1-chronicle.googleapis.com",
    "australia-southeast1": "https://australia-southeast1-chronicle.googleapis.com",
    "me-central2": "https://me-central2-chronicle.googleapis.com",
    "northamerica-northeast2": "https://northamerica-northeast2-chronicle.googleapis.com",
}


class ChronicleError(Exception):
    """Base class for Chronicle client errors."""


class ChronicleAPIError(ChronicleError):
    """The Chronicle API returned a non-success status."""

    def __init__(self, status_code: int, body: str) -> None:
        super().__init__(f"Chronicle API HTTP {status_code}: {body[:500]}")
        self.status_code = status_code
        self.body = body


@dataclass(frozen=True)
class ChronicleConfig:
    """Static config for a Chronicle tenant — non-secret bits only."""

    customer_id: str
    region: str
    base_url: str | None = None  # override of region → URL
    allow_write: bool = False

    def resolved_base_url(self) -> str:
        if self.base_url:
            return self.base_url.rstrip("/")
        url = REGION_BASE_URLS.get(self.region)
        if url is None:
            raise ChronicleError(
                f"Chronicle region {self.region!r} is not in the URL map; "
                f"set base_url= explicitly or use one of {sorted(REGION_BASE_URLS)}"
            )
        return url


@dataclass(frozen=True)
class ChronicleAlertsResult:
    """Result of one ``list_alerts`` call against Chronicle's Detection API."""

    alerts: list[dict[str, Any]] = field(default_factory=list)
    next_page_token: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UdmSearchResult:
    """Result of one UDM Search call.

    ``events`` is whatever Chronicle returned (typed as ``list[dict]`` for
    Phase 2.1 — Phase 2.3 will narrow once the Retro Hunts screen needs
    specific fields).
    """

    events: list[dict[str, Any]] = field(default_factory=list)
    total_events: int | None = None
    more_data_available: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


class ChronicleClient:
    """Chronicle SecOps client.

    The ``http`` argument exists for tests — production callers omit it
    and the client opens its own :class:`HardenedClient` per request.
    """

    name = "chronicle"

    def __init__(
        self,
        cfg: ChronicleConfig,
        *,
        auth: ChronicleAuth,
    ) -> None:
        self._cfg = cfg
        self._auth = auth
        self._base_url = cfg.resolved_base_url()

    @property
    def cfg(self) -> ChronicleConfig:
        return self._cfg

    @property
    def base_url(self) -> str:
        return self._base_url

    def udm_search_url(self) -> str:
        """The URL the client POSTs to for UDM searches.

        Phase 2 keeps this simple — ``{base_url}/v1alpha/{customer_id}:udmSearch``.
        Real Chronicle API paths have evolved over time; the user can
        override the whole base URL in config if the path ever needs more.
        """
        return f"{self._base_url}/v1alpha/{self._cfg.customer_id}:udmSearch"

    def alerts_url(self) -> str:
        """URL for the Chronicle Detection API list-alerts call."""
        return f"{self._base_url}/v1alpha/{self._cfg.customer_id}:listAlerts"

    async def udm_search(
        self,
        query: str,
        *,
        lookback_hours: int = 24 * 30,
        limit: int = 1000,
        end_time: datetime | None = None,
    ) -> UdmSearchResult:
        """Run a UDM Search and return matching events.

        ``query`` is a Chronicle UDM filter expression — see
        :mod:`secops_term.chronicle.retro_hunt` (Phase 2.2) for the
        per-IOC-type query builder.
        """
        if not query.strip():
            raise ChronicleError("UDM search query is empty")
        if limit < 1:
            raise ChronicleError(f"limit must be >= 1, got {limit}")
        if lookback_hours < 1:
            raise ChronicleError(f"lookback_hours must be >= 1, got {lookback_hours}")
        end_dt = end_time if end_time is not None else datetime.now(UTC)
        start_dt = end_dt - timedelta(hours=lookback_hours)

        body = {
            "query": query,
            "time_range": {
                "start_time": _iso(start_dt),
                "end_time": _iso(end_dt),
            },
            "limit": int(limit),
        }
        token = await self._get_token_or_raise()
        url = self.udm_search_url()
        async with HardenedClient(HTTPConfig(response_cap_bytes=50 * 1024 * 1024)) as http:
            resp = await http.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json=body,
            )
        if resp.status_code != 200:
            raise ChronicleAPIError(resp.status_code, resp.text)
        try:
            payload = resp.json()
        except Exception as exc:
            raise ChronicleError(f"Chronicle response was not JSON: {exc}") from exc
        return _parse_udm_search_response(payload)

    async def list_alerts(
        self,
        *,
        since: datetime | None = None,
        limit: int = 100,
    ) -> ChronicleAlertsResult:
        """List Chronicle Detection-API alerts.

        Phase 3.3 wiring for the unified Alerts pipeline. Returns a list
        of raw alert payloads — :mod:`secops_term.alerts.normalize`
        converts them to the unified :class:`Alert` shape.
        """
        if limit < 1 or limit > 5000:
            raise ChronicleError(f"limit must be in [1, 5000], got {limit}")
        token = await self._get_token_or_raise()
        params: dict[str, str] = {"pageSize": str(limit)}
        if since is not None:
            params["startTime"] = _iso(since)
        async with HardenedClient(HTTPConfig(response_cap_bytes=50 * 1024 * 1024)) as http:
            resp = await http.get(
                self.alerts_url(),
                headers={"Authorization": f"Bearer {token}"},
                params=params,
            )
        if resp.status_code != 200:
            raise ChronicleAPIError(resp.status_code, resp.text)
        try:
            payload = resp.json()
        except Exception as exc:
            raise ChronicleError(f"Chronicle response was not JSON: {exc}") from exc
        if not isinstance(payload, dict):
            return ChronicleAlertsResult()
        items = payload.get("alerts")
        alerts = [a for a in items if isinstance(a, dict)] if isinstance(items, list) else []
        next_token = payload.get("nextPageToken")
        return ChronicleAlertsResult(
            alerts=alerts,
            next_page_token=next_token if isinstance(next_token, str) else None,
            raw=payload,
        )

    async def health_check(self) -> HealthStatus:
        """Auth-validating probe: a tight 1-event UDM search.

        Hits the same code path as production searches (auth + base URL +
        endpoint) so a green probe means the next real search will work.
        """
        started = time.monotonic()
        # A query that should return 0 events but exercise auth + endpoint:
        # `principal.ip = "0.0.0.0"` matches nothing useful in real telemetry,
        # the time range is 1 minute, limit is 1.
        try:
            await self.udm_search(
                'principal.ip = "0.0.0.0"',
                lookback_hours=1,
                limit=1,
            )
        except ChronicleAuthError as exc:
            return _failed(f"auth: {exc}", started)
        except ChronicleAPIError as exc:
            # Auth tokens are validated server-side; 401/403 = bad creds.
            if exc.status_code in (401, 403):
                return _failed(f"auth rejected (HTTP {exc.status_code})", started)
            return _failed(f"HTTP {exc.status_code}", started)
        except ChronicleError as exc:
            return _failed(f"{exc}", started)
        except Exception as exc:
            return _failed(f"{type(exc).__name__}: {exc}", started)
        latency_ms = (time.monotonic() - started) * 1000
        return HealthStatus(
            ok=True,
            latency_ms=latency_ms,
            detail=f"{self._cfg.region}/{self._cfg.customer_id}",
            last_checked=datetime.now(UTC),
        )

    async def _get_token_or_raise(self) -> str:
        try:
            return await self._auth.get_token()
        except ChronicleAuthError:
            raise
        except Exception as exc:
            raise ChronicleAuthError(f"auth provider failed: {type(exc).__name__}: {exc}") from exc


def _parse_udm_search_response(payload: dict[str, Any]) -> UdmSearchResult:
    raw_events = payload.get("events")
    events: list[dict[str, Any]] = []
    if isinstance(raw_events, list):
        events = [e for e in raw_events if isinstance(e, dict)]
    total = payload.get("total_events")
    return UdmSearchResult(
        events=events,
        total_events=int(total) if isinstance(total, int) else None,
        more_data_available=bool(payload.get("more_data_available", False)),
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
    "REGION_BASE_URLS",
    "ChronicleAPIError",
    "ChronicleClient",
    "ChronicleConfig",
    "ChronicleError",
    "UdmSearchResult",
]
