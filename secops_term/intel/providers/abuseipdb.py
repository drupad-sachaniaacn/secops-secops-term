"""AbuseIPDB threat-intel provider.

Per brief v3 §6.1. Fetches the AbuseIPDB IP blacklist — a community-curated
list of IP addresses reported for malicious activity — and converts them into
:class:`~secops_term.intel.providers.base.IntelRecord` rows.

Auth: ``Key`` header; keyring ``secops-term:intel.abuseipdb:<instance>``
/ ``api_key``.

Health check: ``GET /api/v2/check?ipAddress=8.8.8.8`` — verifies auth with a
single lookup of a well-known benign IP (Google DNS). Minimal quota cost.

Config:

.. code-block:: toml

    [intel_providers.abuseipdb.default]
    enabled = true
    confidence_minimum = 75   # 25-100; lower = broader, higher = more certain
    limit = 1000              # max IPs per pull (1-10000)

IOC types produced: ``ipv4`` (AbuseIPDB tracks IP addresses only).
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

_BASE_URL = "https://api.abuseipdb.com"
_KEYRING_PROVIDER = "intel.abuseipdb"
_KEYRING_FIELD = "api_key"
_DEFAULT_CONFIDENCE = 75
_DEFAULT_LIMIT = 1000
_MIN_CONFIDENCE = 25
_MAX_CONFIDENCE = 100
_MAX_LIMIT = 10_000
# Well-known probe target — Google Public DNS, consistently low/zero abuse score.
_HEALTH_PROBE_IP = "8.8.8.8"


@PROVIDERS.register("abuseipdb")
class AbuseIPDBProvider:
    """AbuseIPDB intel provider — pulls the IP confidence blacklist."""

    name: ClassVar[str] = "abuseipdb"

    def __init__(
        self,
        instance: str,
        *,
        confidence_minimum: int = _DEFAULT_CONFIDENCE,
        limit: int = _DEFAULT_LIMIT,
    ) -> None:
        self.instance = instance
        self._confidence = max(_MIN_CONFIDENCE, min(_MAX_CONFIDENCE, confidence_minimum))
        self._limit = max(1, min(_MAX_LIMIT, limit))

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> AbuseIPDBProvider:
        raw_conf = cfg.get("confidence_minimum", _DEFAULT_CONFIDENCE)
        raw_limit = cfg.get("limit", _DEFAULT_LIMIT)
        try:
            confidence = int(raw_conf)
        except (TypeError, ValueError):
            confidence = _DEFAULT_CONFIDENCE
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            limit = _DEFAULT_LIMIT
        return cls(instance, confidence_minimum=confidence, limit=limit)

    async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
        """Fetch the AbuseIPDB blacklist and return one IntelRecord per IP.

        The ``since`` parameter is applied post-fetch using the ``lastReportedAt``
        field in each entry (AbuseIPDB has no server-side date filter on the
        blacklist endpoint). Pass ``since`` to limit to recently active IPs.
        """
        token = self._get_token()
        params: dict[str, str | int] = {
            "confidenceMinimum": self._confidence,
            "limit": self._limit,
        }
        try:
            async with HardenedClient() as http:
                resp = await http.get(
                    f"{_BASE_URL}/api/v2/blacklist",
                    params=params,
                    headers={"Key": token, "Accept": "application/json"},
                )
        except Exception:
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
            ip = entry.get("ipAddress")
            if not isinstance(ip, str) or not ip:
                continue
            # Optional `since` filter — AbuseIPDB provides `lastReportedAt`.
            if since is not None:
                last_reported = entry.get("lastReportedAt")
                if isinstance(last_reported, str):
                    try:
                        lr_dt = datetime.fromisoformat(last_reported.replace("Z", "+00:00"))
                        if lr_dt < since:
                            continue
                    except (ValueError, TypeError):
                        pass
            score = entry.get("abuseConfidenceScore")
            isp = str(entry.get("isp") or "")
            usage = str(entry.get("usageType") or "")
            ctx_parts = [p for p in (isp, usage) if p]
            ctx: str | None = " / ".join(ctx_parts)[:200] or None
            records.append(
                IntelRecord(
                    source=f"abuseipdb:{self.instance}",
                    type="ipv4",
                    value=ip,
                    fetched_at=fetched_at,
                    confidence=int(score) if isinstance(score, (int, float)) else None,
                    context=ctx,
                    source_ref=None,
                    tags=(),
                )
            )
        return records

    async def health_check(self) -> HealthStatus:
        """``GET /api/v2/check?ipAddress=8.8.8.8`` — auth-validating, minimal quota cost."""
        started = time.monotonic()
        try:
            token = self._get_token()
        except IntelProviderError as exc:
            return _failed(str(exc), started)
        try:
            async with HardenedClient() as http:
                resp = await http.get(
                    f"{_BASE_URL}/api/v2/check",
                    params={"ipAddress": _HEALTH_PROBE_IP, "maxAgeInDays": "90"},
                    headers={"Key": token, "Accept": "application/json"},
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
        score: int | None = None
        if isinstance(body, dict):
            inner = body.get("data")
            if isinstance(inner, dict):
                raw = inner.get("abuseConfidenceScore")
                if isinstance(raw, int):
                    score = raw
        detail = (
            f"auth ok (probe={_HEALTH_PROBE_IP}, score={score})" if score is not None else "auth ok"
        )
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
                f"(run `secops-term config intel abuseipdb --instance {self.instance}`)"
            )
        return token


def _failed(detail: str, started: float) -> HealthStatus:
    return HealthStatus(
        ok=False,
        latency_ms=(time.monotonic() - started) * 1000,
        detail=detail,
        last_checked=datetime.now(UTC),
    )


__all__ = ["AbuseIPDBProvider"]
