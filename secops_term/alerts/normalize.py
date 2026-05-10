"""Per-source alert normalizers — Chronicle / Vision One / Deep Security → :class:`Alert`.

Each source's API returns a different shape; these functions translate
those raw payloads into the unified :class:`Alert` dataclass. Unknown /
missing fields fall back to safe defaults (severity ``"medium"``,
generated id, current time) rather than dropping the alert outright —
better to surface a partially-extracted alert than to lose it.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from secops_term.alerts.types import (
    KNOWN_SEVERITIES,
    Alert,
    Entity,
    EntityType,
    Severity,
)

# Maps a vendor's severity strings (case-insensitive) to our 5-level scale.
_CHRONICLE_SEVERITY_MAP: dict[str, Severity] = {
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
}

_V1_SEVERITY_MAP: dict[str, Severity] = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# DS uses numeric severities sometimes (1-low, 5-critical) plus strings.
_DS_SEVERITY_STRING_MAP: dict[str, Severity] = {
    "info": "info",
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def normalize_chronicle_alert(payload: dict[str, Any]) -> Alert:
    """Normalize a single Chronicle Detection API alert."""
    alert_id = (
        _coerce_str(payload.get("id"))
        or _coerce_str(payload.get("name"))
        or _fallback_id("chronicle", payload)
    )
    title = (
        _coerce_str(payload.get("ruleName"))
        or _coerce_str(payload.get("detection_name"))
        or _coerce_str(payload.get("title"))
        or "Chronicle alert"
    )
    severity = _map_severity(_coerce_str(payload.get("severity")), _CHRONICLE_SEVERITY_MAP)
    detected_at = _parse_dt(
        _coerce_str(payload.get("detectionTime"))
        or _coerce_str(payload.get("createdTime"))
        or _coerce_str(payload.get("timestamp"))
    )
    entities = _extract_chronicle_entities(payload)
    return Alert(
        id=alert_id,
        source="chronicle",
        severity=severity,
        title=title,
        detected_at=detected_at,
        entities=tuple(entities),
        raw=payload,
        dedupe_key=f"chronicle:{alert_id}",
    )


def normalize_vision_one_alert(payload: dict[str, Any]) -> Alert:
    """Normalize a single Vision One Workbench alert."""
    alert_id = _coerce_str(payload.get("id")) or _fallback_id("vision_one", payload)
    title = (
        _coerce_str(payload.get("model"))
        or _coerce_str(payload.get("alertProvider"))
        or "Vision One alert"
    )
    severity = _map_severity(_coerce_str(payload.get("severity")), _V1_SEVERITY_MAP)
    detected_at = _parse_dt(
        _coerce_str(payload.get("createdDateTime")) or _coerce_str(payload.get("firstSeenDateTime"))
    )
    entities = _extract_v1_entities(payload)
    return Alert(
        id=alert_id,
        source="vision_one",
        severity=severity,
        title=title,
        detected_at=detected_at,
        entities=tuple(entities),
        raw=payload,
        dedupe_key=f"vision_one:{alert_id}",
    )


def normalize_deep_security_alert(payload: dict[str, Any]) -> Alert:
    """Normalize a single Deep Security alert."""
    alert_id = (
        _coerce_str(payload.get("ID"))
        or _coerce_str(payload.get("id"))
        or _fallback_id("deep_security", payload)
    )
    title = (
        _coerce_str(payload.get("name"))
        or _coerce_str(payload.get("description"))
        or "Deep Security alert"
    )
    severity = _ds_severity(payload.get("severity"))
    detected_at = _parse_dt(
        _coerce_str(payload.get("alertedTime")) or _coerce_str(payload.get("creationTime"))
    )
    entities = _extract_ds_entities(payload)
    return Alert(
        id=alert_id,
        source="deep_security",
        severity=severity,
        title=title,
        detected_at=detected_at,
        entities=tuple(entities),
        raw=payload,
        dedupe_key=f"deep_security:{alert_id}",
    )


# Helpers


def _coerce_str(v: Any) -> str | None:
    if isinstance(v, str) and v.strip():
        return v
    if isinstance(v, bool):
        return None
    if isinstance(v, int | float):
        # Numeric IDs (e.g. Deep Security "ID": 42) become "42"; preserves
        # round-trippability through the dedupe_key pipeline.
        return str(v)
    return None


def _map_severity(raw: str | None, mapping: dict[str, Severity]) -> Severity:
    if raw is None:
        return "medium"
    return mapping.get(raw.lower(), "medium")


def _ds_severity(raw: Any) -> Severity:
    """DS severity may be a string or a numeric 1-5 / 1-100 score."""
    if isinstance(raw, str):
        return _map_severity(raw, _DS_SEVERITY_STRING_MAP)
    if isinstance(raw, int):
        if raw >= 90:
            return "critical"
        if raw >= 70:
            return "high"
        if raw >= 40:
            return "medium"
        if raw >= 20:
            return "low"
        return "info"
    return "medium"


def _parse_dt(raw: str | None) -> datetime:
    """Parse an ISO-8601 timestamp; fall back to ``now()`` on failure."""
    if not raw:
        return datetime.now(UTC)
    cleaned = raw
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError:
        return datetime.now(UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _fallback_id(source: str, payload: dict[str, Any]) -> str:
    """Stable hash of the payload for sources that don't provide an id."""
    blob = repr(sorted(payload.items())).encode("utf-8", errors="replace")
    digest = hashlib.sha256(blob).hexdigest()[:16]
    return f"{source}-{digest}"


# Source-specific entity extractors


def _extract_chronicle_entities(payload: dict[str, Any]) -> list[Entity]:
    out: list[Entity] = []
    seen: set[tuple[str, str]] = set()

    def _add(t: EntityType, v: str) -> None:
        v_clean = v.strip()
        if not v_clean:
            return
        key = (t, v_clean)
        if key in seen:
            return
        seen.add(key)
        out.append(Entity(type=t, value=v_clean))

    # Chronicle UDM-style detection payloads commonly nest under "entities"
    # or "principal"/"target".
    raw_entities = payload.get("entities")
    if isinstance(raw_entities, list):
        for item in raw_entities:
            if not isinstance(item, dict):
                continue
            t = _coerce_str(item.get("type"))
            v = _coerce_str(item.get("value")) or _coerce_str(item.get("name"))
            mapped = _CHRONICLE_ENTITY_TYPE_MAP.get((t or "").lower())
            if mapped is not None and v is not None:
                _add(mapped, v)

    for principal_key in ("principal", "target", "src", "dst"):
        block = payload.get(principal_key)
        if not isinstance(block, dict):
            continue
        for ip_v in _flatten_strings(block.get("ip")):
            _add("ip", ip_v)
        for host_v in _flatten_strings(block.get("hostname")):
            _add("host", host_v)
        user_block = block.get("user")
        if isinstance(user_block, dict):
            for user_v in _flatten_strings(user_block.get("userid")):
                _add("user", user_v)

    return out


_CHRONICLE_ENTITY_TYPE_MAP: dict[str, EntityType] = {
    "asset": "host",
    "hostname": "host",
    "user": "user",
    "ip": "ip",
    "ipaddress": "ip",
    "domain": "domain",
    "url": "url",
    "file": "file",
    "process": "process",
    "email": "email",
}


def _extract_v1_entities(payload: dict[str, Any]) -> list[Entity]:
    out: list[Entity] = []
    seen: set[tuple[str, str]] = set()

    def _add(t: EntityType, v: str) -> None:
        v_clean = v.strip()
        if not v_clean:
            return
        key = (t, v_clean)
        if key in seen:
            return
        seen.add(key)
        out.append(Entity(type=t, value=v_clean))

    impacted = payload.get("impactScope") or {}
    if isinstance(impacted, dict):
        for entity in _flatten_dicts(impacted.get("entities")):
            t_raw = (
                (entity.get("entityType") or "").lower()
                if isinstance(entity.get("entityType"), str)
                else ""
            )
            value = entity.get("entityValue")
            mapped = _V1_ENTITY_TYPE_MAP.get(t_raw)
            if mapped and isinstance(value, str):
                _add(mapped, value)
    for host in _flatten_strings(payload.get("endpointHostName")):
        _add("host", host)
    for ip in _flatten_strings(payload.get("ipAddress")):
        _add("ip", ip)
    return out


_V1_ENTITY_TYPE_MAP: dict[str, EntityType] = {
    "host": "host",
    "endpoint": "host",
    "user": "user",
    "ipaddress": "ip",
    "ip": "ip",
    "url": "url",
    "domain": "domain",
    "file": "file",
    "filehash": "file",
    "email": "email",
    "process": "process",
}


def _extract_ds_entities(payload: dict[str, Any]) -> list[Entity]:
    out: list[Entity] = []
    seen: set[tuple[str, str]] = set()

    def _add(t: EntityType, v: str) -> None:
        v_clean = v.strip()
        if not v_clean:
            return
        key = (t, v_clean)
        if key in seen:
            return
        seen.add(key)
        out.append(Entity(type=t, value=v_clean))

    for host in _flatten_strings(payload.get("computerName")):
        _add("host", host)
    for host in _flatten_strings(payload.get("hostname")):
        _add("host", host)
    return out


def _flatten_strings(v: Any) -> list[str]:
    if isinstance(v, str) and v.strip():
        return [v]
    if isinstance(v, list):
        return [s for s in v if isinstance(s, str) and s.strip()]
    return []


def _flatten_dicts(v: Any) -> list[dict[str, Any]]:
    if isinstance(v, list):
        return [d for d in v if isinstance(d, dict)]
    return []


# Title-signature for grouping (used by `dedup.group_alerts`).

_DIGITS_RE = re.compile(r"\d+")
_WHITESPACE_RE = re.compile(r"\s+")


def title_signature(title: str) -> str:
    """Return a normalized form of a title for soft grouping.

    Lowercase, strip digits (timestamps / IDs vary across near-duplicate
    alerts), collapse whitespace.
    """
    s = title.lower()
    s = _DIGITS_RE.sub("#", s)
    s = _WHITESPACE_RE.sub(" ", s).strip()
    return s


__all__ = [
    "KNOWN_SEVERITIES",
    "normalize_chronicle_alert",
    "normalize_deep_security_alert",
    "normalize_vision_one_alert",
    "title_signature",
]
