"""abuse.ch threat-intel provider — URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker.

Per brief v3 §6.1: a single ``auth.abuse.ch`` API token gates all four
sub-feeds. Sub-feed toggles in config:

.. code-block:: toml

    [intel_providers.abuse_ch.default]
    enabled = true
    sub_feeds = ["urlhaus", "malware_bazaar", "threatfox", "feodo_tracker"]

The token is stored in the keyring under
``secops-term:intel.abuse_ch:<instance>`` / ``api_token``.

Health check: ThreatFox ``get_iocs`` with ``days=1`` — auth-validating and
quota-cheap (a single small POST per probe).
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

_KEYRING_PROVIDER = "intel.abuse_ch"
_KEYRING_FIELD = "api_token"

_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
_MBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

_ALL_SUB_FEEDS: tuple[str, ...] = (
    "urlhaus",
    "malware_bazaar",
    "threatfox",
    "feodo_tracker",
)

# ThreatFox returns indicators with these type strings; map to our schema.
_THREATFOX_TYPE_MAP: dict[str, str] = {
    "ip:port": "ipv4",
    "domain": "domain",
    "url": "url",
    "md5_hash": "md5",
    "sha1_hash": "sha1",
    "sha256_hash": "sha256",
    "email": "email",
}


@PROVIDERS.register("abuse_ch")
class AbuseCHProvider:
    """abuse.ch multi-sub-feed intel provider."""

    name: ClassVar[str] = "abuse_ch"

    def __init__(
        self,
        instance: str,
        *,
        sub_feeds: tuple[str, ...] | None = None,
    ) -> None:
        self.instance = instance
        self._sub_feeds: tuple[str, ...] = (
            tuple(sub_feeds) if sub_feeds is not None else _ALL_SUB_FEEDS
        )

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> AbuseCHProvider:
        raw = cfg.get("sub_feeds")
        if raw is None:
            return cls(instance)
        if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
            raise IntelProviderError(f"{cls.name}:{instance}: sub_feeds must be a list of strings")
        unknown = [s for s in raw if s not in _ALL_SUB_FEEDS]
        if unknown:
            raise IntelProviderError(
                f"{cls.name}:{instance}: unknown sub_feeds {unknown!r}; "
                f"valid options are {list(_ALL_SUB_FEEDS)}"
            )
        return cls(instance, sub_feeds=tuple(raw))

    @property
    def sub_feeds(self) -> tuple[str, ...]:
        return self._sub_feeds

    # Public API

    async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
        token = self._get_token()
        records: list[IntelRecord] = []
        async with HardenedClient() as http:
            if "urlhaus" in self._sub_feeds:
                records.extend(await self._pull_urlhaus(http, token))
            if "malware_bazaar" in self._sub_feeds:
                records.extend(await self._pull_mbazaar(http, token))
            if "threatfox" in self._sub_feeds:
                records.extend(await self._pull_threatfox(http, token))
            if "feodo_tracker" in self._sub_feeds:
                records.extend(await self._pull_feodo(http, token))
        if since is not None:
            records = [r for r in records if r.fetched_at >= since]
        return records

    async def health_check(self) -> HealthStatus:
        """Auth-validating probe: ThreatFox ``get_iocs`` with ``days=1``."""
        started = time.monotonic()
        try:
            token = self._get_token()
        except IntelProviderError as exc:
            return _failed(f"{exc}", started)
        try:
            async with HardenedClient() as http:
                resp = await http.post(
                    _THREATFOX_URL,
                    headers={"Auth-Key": token},
                    json={"query": "get_iocs", "days": 1},
                )
        except Exception as exc:
            return _failed(f"{type(exc).__name__}: {exc}", started)
        latency_ms = (time.monotonic() - started) * 1000
        if resp.status_code != 200:
            return _failed(f"HTTP {resp.status_code}", started)
        try:
            payload = resp.json()
        except Exception as exc:
            return _failed(f"non-JSON response: {exc}", started)
        if payload.get("query_status") not in ("ok", "no_result"):
            return _failed(f"query_status={payload.get('query_status')!r}", started)
        return HealthStatus(
            ok=True,
            latency_ms=latency_ms,
            detail=f"threatfox auth ok (query_status={payload.get('query_status')})",
            last_checked=datetime.now(UTC),
        )

    # Sub-feed pullers — each isolated so one feed's failure doesn't block others.

    async def _pull_urlhaus(self, http: HardenedClient, token: str) -> list[IntelRecord]:
        try:
            resp = await http.post(
                _URLHAUS_URL,
                headers={"Auth-Key": token},
                data={"limit": "100"},
            )
        except Exception:
            return []
        if resp.status_code != 200:
            return []
        payload = _safe_json(resp.text)
        if not isinstance(payload, dict):
            return []
        urls = payload.get("urls")
        if not isinstance(urls, list):
            return []
        fetched_at = datetime.now(UTC)
        out: list[IntelRecord] = []
        for entry in urls:
            if not isinstance(entry, dict):
                continue
            url_value = entry.get("url")
            if not isinstance(url_value, str):
                continue
            tags = entry.get("tags") or []
            ref = str(entry.get("id") or entry.get("url_id") or "")
            out.append(
                IntelRecord(
                    source=f"abuse_ch:{self.instance}",
                    type="url",
                    value=url_value,
                    fetched_at=fetched_at,
                    confidence=None,
                    context=str(entry.get("threat") or ""),
                    source_ref=ref or None,
                    tags=tuple(str(t) for t in tags if isinstance(t, str)),
                )
            )
        return out

    async def _pull_mbazaar(self, http: HardenedClient, token: str) -> list[IntelRecord]:
        try:
            resp = await http.post(
                _MBAZAAR_URL,
                headers={"Auth-Key": token},
                data={"query": "get_recent", "selector": "time"},
            )
        except Exception:
            return []
        if resp.status_code != 200:
            return []
        payload = _safe_json(resp.text)
        if not isinstance(payload, dict):
            return []
        if payload.get("query_status") not in ("ok", "no_results"):
            return []
        data = payload.get("data") or []
        if not isinstance(data, list):
            return []
        fetched_at = datetime.now(UTC)
        out: list[IntelRecord] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            tags = entry.get("tags") or []
            tag_tuple = tuple(str(t) for t in tags if isinstance(t, str))
            ref = str(entry.get("sha256_hash") or "")
            ctx = " ".join(
                filter(
                    None,
                    [
                        str(entry.get("file_name") or ""),
                        str(entry.get("signature") or ""),
                    ],
                )
            )[:200]
            for type_, key in (
                ("sha256", "sha256_hash"),
                ("sha1", "sha1_hash"),
                ("md5", "md5_hash"),
            ):
                value = entry.get(key)
                if isinstance(value, str) and value:
                    out.append(
                        IntelRecord(
                            source=f"abuse_ch:{self.instance}",
                            type=type_,
                            value=value,
                            fetched_at=fetched_at,
                            context=ctx or None,
                            source_ref=ref or None,
                            tags=tag_tuple,
                        )
                    )
        return out

    async def _pull_threatfox(self, http: HardenedClient, token: str) -> list[IntelRecord]:
        try:
            resp = await http.post(
                _THREATFOX_URL,
                headers={"Auth-Key": token},
                json={"query": "get_iocs", "days": 7},
            )
        except Exception:
            return []
        if resp.status_code != 200:
            return []
        payload = _safe_json(resp.text)
        if not isinstance(payload, dict):
            return []
        if payload.get("query_status") not in ("ok", "no_result"):
            return []
        data = payload.get("data") or []
        if not isinstance(data, list):
            return []
        fetched_at = datetime.now(UTC)
        out: list[IntelRecord] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            ioc_type_raw = entry.get("ioc_type")
            our_type = _THREATFOX_TYPE_MAP.get(str(ioc_type_raw)) if ioc_type_raw else None
            value = entry.get("ioc")
            if our_type is None or not isinstance(value, str) or not value:
                continue
            # `ip:port` IOCs from ThreatFox come as e.g. "1.2.3.4:443" — drop the port.
            if our_type == "ipv4" and ":" in value:
                value = value.split(":", 1)[0]
            confidence = entry.get("confidence_level")
            tags = entry.get("tags") or []
            out.append(
                IntelRecord(
                    source=f"abuse_ch:{self.instance}",
                    type=our_type,
                    value=value,
                    fetched_at=fetched_at,
                    confidence=int(confidence) if isinstance(confidence, int) else None,
                    context=str(entry.get("malware_printable") or ""),
                    source_ref=str(entry.get("id") or "") or None,
                    tags=tuple(str(t) for t in tags if isinstance(t, str)),
                )
            )
        return out

    async def _pull_feodo(self, http: HardenedClient, token: str) -> list[IntelRecord]:
        try:
            resp = await http.get(_FEODO_URL, headers={"Auth-Key": token})
        except Exception:
            return []
        if resp.status_code != 200:
            return []
        payload = _safe_json(resp.text)
        if not isinstance(payload, list):
            return []
        fetched_at = datetime.now(UTC)
        out: list[IntelRecord] = []
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip_address")
            if not isinstance(ip, str) or not ip:
                continue
            malware = str(entry.get("malware") or "")
            out.append(
                IntelRecord(
                    source=f"abuse_ch:{self.instance}",
                    type="ipv4",
                    value=ip,
                    fetched_at=fetched_at,
                    context=malware or None,
                    source_ref=None,
                    tags=("feodo_tracker",) + ((malware,) if malware else ()),
                )
            )
        return out

    # Helpers

    def _get_token(self) -> str:
        mgr = secrets_mod.get_manager()
        token = mgr.get_secret(_KEYRING_PROVIDER, self.instance, _KEYRING_FIELD)
        if not token:
            raise IntelProviderError(
                f"{self.name}:{self.instance}: no api_token configured "
                f"(run `secops-term config intel abuse_ch --instance {self.instance}`)"
            )
        return token


# Module-level helpers


def _safe_json(text: str) -> Any:
    import json as _json

    try:
        return _json.loads(text)
    except Exception:
        return None


def _failed(detail: str, started: float) -> HealthStatus:
    return HealthStatus(
        ok=False,
        latency_ms=(time.monotonic() - started) * 1000,
        detail=detail,
        last_checked=datetime.now(UTC),
    )
