"""Unified Alert types shared by every source.

Per brief v3 §6.3:

.. code-block:: python

    @dataclass
    class Alert:
        id: str
        source: Literal["chronicle", "vision_one", "deep_security"]
        severity: Literal["info", "low", "medium", "high", "critical"]
        title: str
        detected_at: datetime
        entities: list[Entity]   # users, hosts, IPs, files
        raw: dict                # original payload, kept for reference
        dedupe_key: str          # source + correlation id

The ``raw`` payload is preserved so consumers (the Alerts screen, future
playbook steps) can pull source-specific fields without forcing this
module to model every vendor's schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
Source = Literal["chronicle", "vision_one", "deep_security"]
EntityType = Literal["user", "host", "ip", "file", "url", "domain", "process", "email"]

KNOWN_SEVERITIES: tuple[Severity, ...] = (
    "info",
    "low",
    "medium",
    "high",
    "critical",
)


@dataclass(frozen=True)
class Entity:
    """A user / host / IP / file / URL referenced by an alert."""

    type: EntityType
    value: str


@dataclass(frozen=True)
class Alert:
    """A normalized alert from any of the three configured sources."""

    id: str
    source: Source
    severity: Severity
    title: str
    detected_at: datetime
    entities: tuple[Entity, ...]
    raw: dict[str, Any] = field(default_factory=dict)
    dedupe_key: str = ""

    def primary_entity(self) -> Entity | None:
        """Return the most representative entity for grouping.

        Phase 3.3 picks the first entity in canonical order:
        host > user > ip > domain > url > file > process > email.
        """
        if not self.entities:
            return None
        order = {t: i for i, t in enumerate(_PRIMARY_ENTITY_ORDER)}
        return min(
            self.entities,
            key=lambda e: (order.get(e.type, 99), e.value),
        )


_PRIMARY_ENTITY_ORDER: tuple[EntityType, ...] = (
    "host",
    "user",
    "ip",
    "domain",
    "url",
    "file",
    "process",
    "email",
)


@dataclass(frozen=True)
class AlertGroup:
    """A cluster of near-duplicate alerts (per brief §6.3 grouping rule)."""

    representative: Alert
    members: tuple[Alert, ...]

    @property
    def count(self) -> int:
        return len(self.members)


__all__ = [
    "KNOWN_SEVERITIES",
    "Alert",
    "AlertGroup",
    "Entity",
    "EntityType",
    "Severity",
    "Source",
]
