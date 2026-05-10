"""Alert ingest, normalization, and dedupe across Chronicle, V1, and DS. Phase 3."""

from secops_term.alerts.dedup import (
    DEFAULT_GROUP_WINDOW,
    dedupe_alerts,
    group_alerts,
)
from secops_term.alerts.ingest import IngestResult, SourceResult, ingest_all
from secops_term.alerts.normalize import (
    normalize_chronicle_alert,
    normalize_deep_security_alert,
    normalize_vision_one_alert,
    title_signature,
)
from secops_term.alerts.types import (
    KNOWN_SEVERITIES,
    Alert,
    AlertGroup,
    Entity,
    EntityType,
    Severity,
    Source,
)

__all__ = [
    "DEFAULT_GROUP_WINDOW",
    "KNOWN_SEVERITIES",
    "Alert",
    "AlertGroup",
    "Entity",
    "EntityType",
    "IngestResult",
    "Severity",
    "Source",
    "SourceResult",
    "dedupe_alerts",
    "group_alerts",
    "ingest_all",
    "normalize_chronicle_alert",
    "normalize_deep_security_alert",
    "normalize_vision_one_alert",
    "title_signature",
]
