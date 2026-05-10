"""NVD (National Vulnerability Database) threat-intel provider.

Per brief v3 §6.1. Pulls recently published CVEs from the NIST NVD REST API
v2 and converts them into :class:`~secops_term.intel.providers.base.IntelRecord`
rows of type ``cve``.

Auth: optional ``apiKey`` header. NVD is a public government API that works
without authentication, but rate-limits unauthenticated requests more
aggressively (5 req/30 s vs 50 req/30 s). The API key lives in the keyring
under ``secops-term:intel.nvd:<instance>`` / ``api_key`` and is passed when
present; pull succeeds either way.

Health check: ``GET /rest/json/cves/2.0?resultsPerPage=1&startIndex=0`` —
lightweight single-result fetch; validates reachability and (when a key is
configured) API key acceptance.

Config:

.. code-block:: toml

    [intel_providers.nvd.default]
    enabled = true
    days_back = 7        # publication window when no ``since`` is given
    min_cvss_v3 = 7.0    # drop CVEs with a CVSS v3 base score below this
    limit = 200          # max CVEs per pull (1-2000, NVD hard cap)

IOC types produced: ``cve`` (``CVE-YYYY-XXXXX`` identifiers).
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from secops_term.core import secrets as secrets_mod
from secops_term.core.health import HealthStatus
from secops_term.core.http import HardenedClient
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers.base import IntelRecord

_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail"
_KEYRING_PROVIDER = "intel.nvd"
_KEYRING_FIELD = "api_key"
_DEFAULT_DAYS_BACK = 7
_DEFAULT_MIN_CVSS = 7.0
_DEFAULT_LIMIT = 200
_MAX_LIMIT = 2000
# NVD timestamp format: "YYYY-MM-DDTHH:MM:SS.000"
_NVD_DT_FMT = "%Y-%m-%dT%H:%M:%S.000"


@PROVIDERS.register("nvd")
class NVDProvider:
    """NIST NVD intel provider — pulls recently published CVEs."""

    name: ClassVar[str] = "nvd"

    def __init__(
        self,
        instance: str,
        *,
        days_back: int = _DEFAULT_DAYS_BACK,
        min_cvss_v3: float = _DEFAULT_MIN_CVSS,
        limit: int = _DEFAULT_LIMIT,
    ) -> None:
        self.instance = instance
        self._days_back = max(1, days_back)
        self._min_cvss_v3 = max(0.0, min(10.0, min_cvss_v3))
        self._limit = max(1, min(_MAX_LIMIT, limit))

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> NVDProvider:
        try:
            days_back = int(cfg.get("days_back", _DEFAULT_DAYS_BACK))
        except (TypeError, ValueError):
            days_back = _DEFAULT_DAYS_BACK
        try:
            min_cvss = float(cfg.get("min_cvss_v3", _DEFAULT_MIN_CVSS))
        except (TypeError, ValueError):
            min_cvss = _DEFAULT_MIN_CVSS
        try:
            limit = int(cfg.get("limit", _DEFAULT_LIMIT))
        except (TypeError, ValueError):
            limit = _DEFAULT_LIMIT
        return cls(instance, days_back=days_back, min_cvss_v3=min_cvss, limit=limit)

    async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
        """Fetch recently published CVEs from NVD.

        When ``since`` is given, it sets the ``pubStartDate`` query parameter.
        Otherwise the window is the last ``days_back`` days ending now. Results
        are post-filtered to drop CVEs whose CVSS v3 base score is below
        ``min_cvss_v3`` (use 0.0 to disable filtering).
        """
        api_key = self._get_api_key_optional()
        now = datetime.now(UTC)
        start = since if since is not None else (now - timedelta(days=self._days_back))
        params: dict[str, str | int] = {
            "pubStartDate": start.strftime(_NVD_DT_FMT),
            "pubEndDate": now.strftime(_NVD_DT_FMT),
            "resultsPerPage": self._limit,
            "startIndex": 0,
        }
        headers: dict[str, str] = {}
        if api_key:
            headers["apiKey"] = api_key
        try:
            async with HardenedClient() as http:
                resp = await http.get(_BASE_URL, params=params, headers=headers)
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
        vulns = payload.get("vulnerabilities")
        if not isinstance(vulns, list):
            return []
        fetched_at = datetime.now(UTC)
        records: list[IntelRecord] = []
        for vuln_wrap in vulns:
            if not isinstance(vuln_wrap, dict):
                continue
            cve = vuln_wrap.get("cve")
            if not isinstance(cve, dict):
                continue
            cve_id = cve.get("id")
            if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
                continue
            # CVSS v3 score — try cvssMetricV31 first, then v30.
            cvss_score, severity = _extract_cvss_v3(cve)
            if (
                self._min_cvss_v3 > 0.0
                and cvss_score is not None
                and cvss_score < self._min_cvss_v3
            ):
                continue
            description = _extract_description(cve)
            tags = (severity.lower(),) if severity else ()
            records.append(
                IntelRecord(
                    source=f"nvd:{self.instance}",
                    type="cve",
                    value=cve_id,
                    fetched_at=fetched_at,
                    confidence=None,
                    context=description[:200] if description else None,
                    source_ref=f"{_NVD_DETAIL_URL}/{cve_id}",
                    tags=tags,
                )
            )
        return records

    async def health_check(self) -> HealthStatus:
        """``GET /rest/json/cves/2.0?resultsPerPage=1`` — lightweight reachability probe."""
        started = time.monotonic()
        api_key = self._get_api_key_optional()
        headers: dict[str, str] = {}
        if api_key:
            headers["apiKey"] = api_key
        try:
            async with HardenedClient() as http:
                resp = await http.get(
                    _BASE_URL,
                    params={"resultsPerPage": 1, "startIndex": 0},
                    headers=headers,
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
        total = body.get("totalResults") if isinstance(body, dict) else None
        auth_note = "authenticated" if api_key else "unauthenticated"
        detail = (
            f"reachable, {auth_note}, totalResults={total}"
            if total is not None
            else f"reachable, {auth_note}"
        )
        return HealthStatus(
            ok=True,
            latency_ms=latency_ms,
            detail=detail,
            last_checked=datetime.now(UTC),
        )

    def _get_api_key_optional(self) -> str | None:
        """Return the NVD API key from keyring, or ``None`` if not configured."""
        mgr = secrets_mod.get_manager()
        return mgr.get_secret(_KEYRING_PROVIDER, self.instance, _KEYRING_FIELD) or None


# Module-level helpers


def _extract_cvss_v3(cve: dict[str, Any]) -> tuple[float | None, str]:
    """Return (base_score, severity) from the CVE's CVSS v3 metrics, or (None, '')."""
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None, ""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key)
        if not isinstance(metric_list, list) or not metric_list:
            continue
        # Prefer the "Primary" source when multiple entries exist.
        primary = next(
            (m for m in metric_list if isinstance(m, dict) and m.get("type") == "Primary"),
            metric_list[0],
        )
        if not isinstance(primary, dict):
            continue
        cvss_data = primary.get("cvssData")
        if not isinstance(cvss_data, dict):
            continue
        score = cvss_data.get("baseScore")
        severity = str(cvss_data.get("baseSeverity") or "")
        if isinstance(score, (int, float)):
            return float(score), severity
    return None, ""


def _extract_description(cve: dict[str, Any]) -> str:
    """Return the first English description from the CVE, or ''."""
    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return ""
    for desc in descriptions:
        if not isinstance(desc, dict):
            continue
        if desc.get("lang") == "en":
            value = desc.get("value")
            if isinstance(value, str):
                return value
    return ""


def _failed(detail: str, started: float) -> HealthStatus:
    return HealthStatus(
        ok=False,
        latency_ms=(time.monotonic() - started) * 1000,
        detail=detail,
        last_checked=datetime.now(UTC),
    )


__all__ = ["NVDProvider"]
