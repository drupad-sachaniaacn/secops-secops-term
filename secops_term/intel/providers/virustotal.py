"""VirusTotal threat-intel provider.

Per brief v3 §6.1. Uses the VT Intelligence Search API to pull recently
detected malware artefacts. Community (non-Intelligence) keys will receive
an empty list from ``pull()`` — health-check still validates auth.

Auth: ``x-apikey`` header; keyring ``secops-term:intel.virustotal:<instance>``
/ ``api_key``.

Health check: ``GET /api/v3/users/{owner}`` — quota-free (no VT scan credits
consumed). ``owner`` is the VT username, set via ``owner = "..."`` in config.

Config:

.. code-block:: toml

    [intel_providers.virustotal.default]
    enabled = true
    owner = "your_vt_username"      # required for the health probe
    query = "type:malware p:5+"     # VT Intelligence GNQL (optional)
    limit = 40                      # max results per pull (1-300)

IOC types produced: ``sha256``, ``sha1``, ``md5`` (one record per hash field
present in each matched file object).
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

_BASE_URL = "https://www.virustotal.com"
_KEYRING_PROVIDER = "intel.virustotal"
_KEYRING_FIELD = "api_key"
_DEFAULT_QUERY = "type:malware p:5+"
_DEFAULT_LIMIT = 40


@PROVIDERS.register("virustotal")
class VirusTotalProvider:
    """VirusTotal intel provider — pulls recently detected malware via Intelligence Search."""

    name: ClassVar[str] = "virustotal"

    def __init__(
        self,
        instance: str,
        *,
        owner: str = "",
        query: str = _DEFAULT_QUERY,
        limit: int = _DEFAULT_LIMIT,
    ) -> None:
        self.instance = instance
        self._owner = owner
        self._query = query
        self._limit = max(1, min(300, limit))

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> VirusTotalProvider:
        owner = str(cfg.get("owner") or "")
        query = str(cfg.get("query") or _DEFAULT_QUERY)
        raw_limit = cfg.get("limit", _DEFAULT_LIMIT)
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            limit = _DEFAULT_LIMIT
        return cls(instance, owner=owner, query=query, limit=limit)

    async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
        """Pull malware file IOCs from VT Intelligence Search.

        Returns an empty list for Community keys (HTTP 403 from the Intelligence
        Search endpoint) without raising — operators should expect this.
        """
        token = self._get_token()
        params: dict[str, str | int] = {
            "query": self._query,
            "limit": self._limit,
            "order": "last_submission_date-",
        }
        try:
            async with HardenedClient() as http:
                resp = await http.get(
                    f"{_BASE_URL}/api/v3/intelligence/search",
                    params=params,
                    headers={"x-apikey": token},
                )
        except Exception:
            return []
        if resp.status_code in (401, 403):
            # Community key or no Intelligence API access — degrade gracefully.
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
        for obj in data:
            if not isinstance(obj, dict):
                continue
            attrs = obj.get("attributes")
            if not isinstance(attrs, dict):
                continue
            # Filter by last_submission_date when `since` is supplied.
            last_sub = attrs.get("last_submission_date")
            if since is not None and last_sub is not None:
                try:
                    obj_dt = datetime.fromtimestamp(int(last_sub), tz=UTC)
                    if obj_dt < since:
                        continue
                except (ValueError, TypeError, OSError):
                    pass
            tags_raw = attrs.get("tags") or []
            tags = tuple(str(t) for t in tags_raw if isinstance(t, str))
            malware_label = _pick_malware_name(attrs)
            ctx = malware_label[:200] if malware_label else None
            obj_id = str(obj.get("id") or "")
            for type_, key in (
                ("sha256", "sha256"),
                ("sha1", "sha1"),
                ("md5", "md5"),
            ):
                value = attrs.get(key)
                if isinstance(value, str) and value:
                    records.append(
                        IntelRecord(
                            source=f"virustotal:{self.instance}",
                            type=type_,
                            value=value,
                            fetched_at=fetched_at,
                            context=ctx,
                            source_ref=obj_id or None,
                            tags=tags,
                        )
                    )
        return records

    async def health_check(self) -> HealthStatus:
        """``GET /api/v3/users/{owner}`` — quota-free auth probe.

        Returns ``ok=False`` immediately if ``owner`` is not set in config —
        operators need to add ``owner = "your_vt_username"`` to the config block.
        """
        started = time.monotonic()
        if not self._owner:
            return HealthStatus(
                ok=False,
                latency_ms=(time.monotonic() - started) * 1000,
                detail="owner not configured (add owner = '...' to config.toml)",
                last_checked=datetime.now(UTC),
            )
        try:
            token = self._get_token()
        except IntelProviderError as exc:
            return _failed(str(exc), started)
        try:
            async with HardenedClient() as http:
                resp = await http.get(
                    f"{_BASE_URL}/api/v3/users/{self._owner}",
                    headers={"x-apikey": token},
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
        quota_detail = _extract_quota_detail(body)
        detail = f"auth ok ({quota_detail})" if quota_detail else "auth ok"
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
                f"(run `secops-term config intel virustotal --instance {self.instance}`)"
            )
        return token


# Module-level helpers


def _pick_malware_name(attrs: dict[str, Any]) -> str:
    """Return the most informative malware label from VT file attributes."""
    classification = attrs.get("popular_threat_classification")
    if isinstance(classification, dict):
        label = classification.get("suggested_threat_label")
        if isinstance(label, str) and label:
            return label
    meaningful = attrs.get("meaningful_name")
    if isinstance(meaningful, str) and meaningful:
        return meaningful
    return ""


def _extract_quota_detail(body: Any) -> str:
    """Parse API quota from /users/<owner> response, return display string or ''."""
    if not isinstance(body, dict):
        return ""
    data = body.get("data")
    if not isinstance(data, dict):
        return ""
    attrs = data.get("attributes")
    if not isinstance(attrs, dict):
        return ""
    quotas = attrs.get("quotas")
    if not isinstance(quotas, dict):
        return ""
    api_q = quotas.get("api_requests_daily")
    if not isinstance(api_q, dict):
        return ""
    used = api_q.get("used")
    allowed = api_q.get("allowed")
    if used is not None and allowed is not None:
        return f"quota {used}/{allowed} today"
    return ""


def _failed(detail: str, started: float) -> HealthStatus:
    return HealthStatus(
        ok=False,
        latency_ms=(time.monotonic() - started) * 1000,
        detail=detail,
        last_checked=datetime.now(UTC),
    )


__all__ = ["VirusTotalProvider"]
