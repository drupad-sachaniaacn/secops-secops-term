"""Unified alert ingest from Chronicle + Vision One + Deep Security.

Per brief v3 §6.3. The CLI (``secops-term alerts list``) and the Alerts
Textual screen both call into :func:`ingest_all`, which:

1. Builds whichever of the three clients are configured.
2. Calls each client's ``list_alerts`` (or Workbench equivalent).
3. Normalizes each source's payloads to :class:`Alert`.
4. Deduplicates by ``dedupe_key``.
5. Optionally groups near-duplicates by ``(title_signature, primary_entity)``.

A failure on one source does not block the others — that source's
:class:`SourceResult` records the error.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from secops_term.alerts import dedup, normalize
from secops_term.alerts.types import Alert, AlertGroup, Source
from secops_term.chronicle import factory as chronicle_factory
from secops_term.chronicle.client import ChronicleError
from secops_term.trendmicro import factory as tm_factory
from secops_term.trendmicro.deep_security import DeepSecurityError
from secops_term.trendmicro.vision_one import VisionOneError


@dataclass(frozen=True)
class SourceResult:
    """Outcome of one ingest source."""

    source: Source
    alerts: list[Alert] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class IngestResult:
    """Aggregate of all source results plus dedup/group output."""

    per_source: list[SourceResult]
    alerts: list[Alert]  # post-dedup (each unique alert once)
    groups: list[AlertGroup]  # grouped per brief §6.3

    @property
    def total(self) -> int:
        return len(self.alerts)

    @property
    def errors(self) -> list[SourceResult]:
        return [s for s in self.per_source if not s.ok]


async def ingest_all(
    *,
    cfg_data: Mapping[str, Any] | None = None,
    since: datetime | None = None,
    limit: int = 100,
) -> IngestResult:
    """Pull from every configured source and return a deduped + grouped result."""
    per_source: list[SourceResult] = []

    chronicle_result = await _ingest_chronicle(cfg_data=cfg_data, since=since, limit=limit)
    if chronicle_result is not None:
        per_source.append(chronicle_result)

    v1_result = await _ingest_vision_one(cfg_data=cfg_data, since=since, limit=limit)
    if v1_result is not None:
        per_source.append(v1_result)

    ds_result = await _ingest_deep_security(cfg_data=cfg_data, since=since, limit=limit)
    if ds_result is not None:
        per_source.append(ds_result)

    raw_alerts: list[Alert] = []
    for src in per_source:
        raw_alerts.extend(src.alerts)
    deduped = dedup.dedupe_alerts(raw_alerts)
    groups = dedup.group_alerts(deduped)
    return IngestResult(per_source=per_source, alerts=deduped, groups=groups)


# Per-source helpers


async def _ingest_chronicle(
    *,
    cfg_data: Mapping[str, Any] | None,
    since: datetime | None,
    limit: int,
) -> SourceResult | None:
    try:
        client = chronicle_factory.build_chronicle_client(cfg_data=cfg_data)
    except ChronicleError as exc:
        return SourceResult(source="chronicle", alerts=[], error=f"factory: {exc}")
    if client is None:
        return None
    try:
        result = await client.list_alerts(since=since, limit=limit)
    except Exception as exc:
        return SourceResult(
            source="chronicle",
            alerts=[],
            error=f"{type(exc).__name__}: {exc}",
        )
    alerts = [normalize.normalize_chronicle_alert(a) for a in result.alerts]
    return SourceResult(source="chronicle", alerts=alerts)


async def _ingest_vision_one(
    *,
    cfg_data: Mapping[str, Any] | None,
    since: datetime | None,
    limit: int,
) -> SourceResult | None:
    try:
        client = tm_factory.build_vision_one_client(cfg_data=cfg_data)
    except VisionOneError as exc:
        return SourceResult(source="vision_one", alerts=[], error=f"factory: {exc}")
    if client is None:
        return None
    try:
        result = await client.list_workbench_alerts(since=since, limit=min(limit, 1000))
    except Exception as exc:
        return SourceResult(
            source="vision_one",
            alerts=[],
            error=f"{type(exc).__name__}: {exc}",
        )
    alerts = [normalize.normalize_vision_one_alert(a) for a in result.alerts]
    return SourceResult(source="vision_one", alerts=alerts)


async def _ingest_deep_security(
    *,
    cfg_data: Mapping[str, Any] | None,
    since: datetime | None,
    limit: int,
) -> SourceResult | None:
    try:
        client = tm_factory.build_deep_security_client(cfg_data=cfg_data)
    except DeepSecurityError as exc:
        return SourceResult(source="deep_security", alerts=[], error=f"factory: {exc}")
    if client is None:
        return None
    try:
        result = await client.list_alerts(since=since, limit=limit)
    except Exception as exc:
        return SourceResult(
            source="deep_security",
            alerts=[],
            error=f"{type(exc).__name__}: {exc}",
        )
    alerts = [normalize.normalize_deep_security_alert(a) for a in result.alerts]
    return SourceResult(source="deep_security", alerts=alerts)


__all__ = ["IngestResult", "SourceResult", "ingest_all"]
