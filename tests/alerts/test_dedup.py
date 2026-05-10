"""Alert dedupe + grouping."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from secops_term.alerts.dedup import dedupe_alerts, group_alerts
from secops_term.alerts.types import Alert, Entity


def _alert(
    *,
    id: str = "x",
    source: str = "chronicle",
    severity: str = "high",
    title: str = "Suspicious PowerShell",
    detected_at: datetime | None = None,
    entities: tuple[Entity, ...] = (),
) -> Alert:
    return Alert(
        id=id,
        source=source,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        title=title,
        detected_at=detected_at if detected_at is not None else datetime.now(UTC),
        entities=entities,
        raw={},
        dedupe_key=f"{source}:{id}",
    )


# dedupe_alerts


def test_dedupe_drops_same_dedupe_key() -> None:
    a1 = _alert(id="1")
    a2 = _alert(id="1")  # same dedupe_key
    a3 = _alert(id="2")
    deduped = dedupe_alerts([a1, a2, a3])
    assert len(deduped) == 2


def test_dedupe_preserves_first_seen_order() -> None:
    a1 = _alert(id="1")
    a2 = _alert(id="2")
    a3 = _alert(id="1")
    deduped = dedupe_alerts([a1, a2, a3])
    assert deduped == [a1, a2]


def test_dedupe_distinct_sources_keep_separately() -> None:
    a_chr = _alert(id="x", source="chronicle")
    a_v1 = _alert(id="x", source="vision_one")
    deduped = dedupe_alerts([a_chr, a_v1])
    assert len(deduped) == 2  # different dedupe_key prefixes


# group_alerts


def test_group_alerts_clusters_by_title_and_entity() -> None:
    host = (Entity(type="host", value="WIN-01"),)
    a1 = _alert(
        id="1",
        title="Suspicious PowerShell",
        entities=host,
        detected_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
    )
    a2 = _alert(
        id="2",
        title="Suspicious PowerShell",  # same signature
        entities=host,
        detected_at=datetime(2026, 1, 1, 12, 30, 0, tzinfo=UTC),
    )
    groups = group_alerts([a1, a2])
    assert len(groups) == 1
    assert groups[0].count == 2


def test_group_alerts_separates_different_entities() -> None:
    a1 = _alert(
        id="1",
        title="Suspicious PowerShell",
        entities=(Entity(type="host", value="WIN-01"),),
    )
    a2 = _alert(
        id="2",
        title="Suspicious PowerShell",
        entities=(Entity(type="host", value="WIN-02"),),
    )
    groups = group_alerts([a1, a2])
    assert len(groups) == 2


def test_group_alerts_separates_outside_window() -> None:
    host = (Entity(type="host", value="WIN-01"),)
    a1 = _alert(
        id="1",
        title="Suspicious PowerShell",
        entities=host,
        detected_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
    )
    a2 = _alert(
        id="2",
        title="Suspicious PowerShell",
        entities=host,
        detected_at=datetime(2026, 1, 1, 14, 0, 0, tzinfo=UTC),  # 2h later
    )
    groups = group_alerts([a1, a2])
    assert len(groups) == 2  # outside default 1h window


def test_group_alerts_normalizes_titles_with_digits() -> None:
    """Per `title_signature`: digits are stripped, so titles differing only
    in IDs/timestamps should group together."""
    host = (Entity(type="host", value="WIN-01"),)
    a1 = _alert(
        id="1",
        title="Login failure user-123 at 10:00",
        entities=host,
        detected_at=datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC),
    )
    a2 = _alert(
        id="2",
        title="Login failure user-456 at 10:30",
        entities=host,
        detected_at=datetime(2026, 1, 1, 10, 30, 0, tzinfo=UTC),
    )
    groups = group_alerts([a1, a2])
    assert len(groups) == 1


def test_group_alerts_representative_is_newest() -> None:
    host = (Entity(type="host", value="WIN-01"),)
    older = _alert(
        id="1",
        title="x",
        entities=host,
        detected_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
    )
    newer = _alert(
        id="2",
        title="x",
        entities=host,
        detected_at=datetime(2026, 1, 1, 12, 30, 0, tzinfo=UTC),
    )
    groups = group_alerts([older, newer])
    assert len(groups) == 1
    assert groups[0].representative.id == "2"


def test_group_alerts_custom_window() -> None:
    host = (Entity(type="host", value="WIN-01"),)
    a1 = _alert(
        id="1",
        title="x",
        entities=host,
        detected_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
    )
    a2 = _alert(
        id="2",
        title="x",
        entities=host,
        detected_at=datetime(2026, 1, 1, 14, 0, 0, tzinfo=UTC),
    )
    # 2h custom window - should fit both
    groups = group_alerts([a1, a2], window=timedelta(hours=3))
    assert len(groups) == 1


def test_group_alerts_empty_input() -> None:
    assert group_alerts([]) == []


def test_primary_entity_canonical_order() -> None:
    a = _alert(
        entities=(
            Entity(type="ip", value="1.1.1.1"),
            Entity(type="host", value="WIN-01"),
            Entity(type="user", value="alice"),
        )
    )
    primary = a.primary_entity()
    assert primary is not None
    assert primary.type == "host"  # host > user > ip per the canonical order


def test_primary_entity_returns_none_for_empty() -> None:
    a = _alert(entities=())
    assert a.primary_entity() is None
