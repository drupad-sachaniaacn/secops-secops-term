"""IOC store: upsert, list, count, search, sources, error paths."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secops_term.core import db as core_db
from secops_term.intel import store as store_mod
from secops_term.intel.providers.base import IntelRecord


def _record(
    *,
    source: str = "otx:default",
    type_: str = "sha256",
    value: str | None = None,
    fetched_at: datetime | None = None,
    confidence: int | None = None,
    context: str | None = None,
    source_ref: str | None = None,
    tags: tuple[str, ...] = (),
) -> IntelRecord:
    return IntelRecord(
        source=source,
        type=type_,
        value=value if value is not None else ("a" * 64),
        fetched_at=fetched_at if fetched_at is not None else datetime.now(UTC),
        confidence=confidence,
        context=context,
        source_ref=source_ref,
        tags=tags,
    )


# Upsert


def test_upsert_new_returns_is_new(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    rec = _record()
    ioc_id, is_new = store.upsert(rec)
    assert ioc_id > 0
    assert is_new is True


def test_upsert_existing_returns_not_new(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    first = _record(fetched_at=datetime(2026, 1, 1, tzinfo=UTC))
    second = _record(
        source="vt:default",
        fetched_at=datetime(2026, 2, 1, tzinfo=UTC),
    )
    id_a, new_a = store.upsert(first)
    id_b, new_b = store.upsert(second)
    assert id_a == id_b
    assert new_a is True
    assert new_b is False


def test_upsert_updates_last_seen(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    first = _record(fetched_at=datetime(2026, 1, 1, tzinfo=UTC))
    second = _record(fetched_at=datetime(2026, 2, 1, tzinfo=UTC))
    store.upsert(first)
    store.upsert(second)
    rec = store.get("sha256", "a" * 64)
    assert rec is not None
    assert rec.first_seen == datetime(2026, 1, 1, tzinfo=UTC)
    assert rec.last_seen == datetime(2026, 2, 1, tzinfo=UTC)


def test_upsert_normalizes_value(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    # Two records with semantically equal but differently-cased values
    # should collapse to one row.
    a = _record(type_="domain", value="Example.COM.", fetched_at=datetime(2026, 1, 1, tzinfo=UTC))
    b = _record(type_="domain", value="example.com", fetched_at=datetime(2026, 2, 1, tzinfo=UTC))
    id_a, new_a = store.upsert(a)
    id_b, new_b = store.upsert(b)
    assert id_a == id_b
    assert new_a is True
    assert new_b is False
    assert store.count() == 1
    rec = store.get("domain", "EXAMPLE.com")
    assert rec is not None
    assert rec.value == "example.com"


def test_upsert_invalid_value_raises(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    with pytest.raises(ValueError):
        store.upsert(_record(type_="ipv4", value="not-an-ip"))


def test_upsert_appends_source_each_call(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    rec1 = _record(source="otx:default", source_ref="pulse-1")
    rec2 = _record(source="vt:default", source_ref="vt-1")
    rec3 = _record(source="otx:default", source_ref="pulse-2")
    ioc_id, _ = store.upsert(rec1)
    store.upsert(rec2)
    store.upsert(rec3)
    sources = store.sources_for(ioc_id)
    assert len(sources) == 3
    assert {s.source for s in sources} == {"otx:default", "vt:default"}


def test_upsert_confidence_coalesces(
    migrated_db: core_db.Database,
) -> None:
    """A None confidence on a re-observation must not overwrite a prior value."""
    store = store_mod.IOCStore(migrated_db)
    store.upsert(_record(confidence=80))
    store.upsert(_record(confidence=None))
    rec = store.get("sha256", "a" * 64)
    assert rec is not None
    assert rec.confidence == 80


def test_bulk_upsert_returns_results(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    records = [_record(value=h * 64) for h in ["a", "b", "c"]]
    out = store.bulk_upsert(records)
    assert len(out) == 3
    assert all(is_new for _, is_new in out)
    assert store.count() == 3


# List / count / search


def test_list_returns_newest_first(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i, h in enumerate(["a", "b", "c"]):
        store.upsert(_record(value=h * 64, fetched_at=base + timedelta(days=i)))
    rows = store.find()
    assert [r.value for r in rows] == ["c" * 64, "b" * 64, "a" * 64]


def test_list_filters_by_type(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    store.upsert(_record(type_="sha256", value="a" * 64))
    store.upsert(_record(type_="ipv4", value="1.2.3.4"))
    rows = store.find(type_="ipv4")
    assert len(rows) == 1
    assert rows[0].value == "1.2.3.4"


def test_list_filters_by_since(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    old = _record(value="a" * 64, fetched_at=datetime(2025, 1, 1, tzinfo=UTC))
    new = _record(value="b" * 64, fetched_at=datetime(2026, 6, 1, tzinfo=UTC))
    store.upsert(old)
    store.upsert(new)
    rows = store.find(since=datetime(2026, 1, 1, tzinfo=UTC))
    assert [r.value for r in rows] == ["b" * 64]


def test_list_limit_and_offset(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(5):
        store.upsert(_record(value=str(i) * 64, fetched_at=base + timedelta(days=i)))
    page1 = store.find(limit=2)
    page2 = store.find(limit=2, offset=2)
    assert len(page1) == 2
    assert len(page2) == 2
    assert page1[0].value != page2[0].value


def test_list_rejects_huge_limit(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    with pytest.raises(store_mod.IOCStoreError):
        store.find(limit=20_000)


def test_list_rejects_negative_offset(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    with pytest.raises(store_mod.IOCStoreError):
        store.find(offset=-1)


def test_list_rejects_unknown_type(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    with pytest.raises(store_mod.IOCStoreError):
        store.find(type_="not-a-type")


def test_count_total_and_by_type(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    store.upsert(_record(type_="sha256", value="a" * 64))
    store.upsert(_record(type_="ipv4", value="1.2.3.4"))
    store.upsert(_record(type_="ipv4", value="5.6.7.8"))
    assert store.count() == 3
    assert store.count(type_="ipv4") == 2
    assert store.count(type_="sha256") == 1


def test_search_substring(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    store.upsert(_record(type_="domain", value="evil.example.com"))
    store.upsert(_record(type_="domain", value="benign.example.org"))
    rows = store.search("example.com")
    assert len(rows) == 1
    assert rows[0].value == "evil.example.com"


def test_search_empty_returns_empty(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    store.upsert(_record(value="a" * 64))
    assert store.search("") == []
    assert store.search("   ") == []


def test_search_escapes_like_wildcards(
    migrated_db: core_db.Database,
) -> None:
    """``_`` is a single-char LIKE wildcard; we escape so it matches literally."""
    store = store_mod.IOCStore(migrated_db)
    store.upsert(_record(type_="email", value="axb@example.com"))
    store.upsert(_record(type_="email", value="a_b@example.com"))
    rows = store.search("a_b")
    # Without escaping, `a_b` would also match `axb` (the `_` matches `x`).
    # With escaping, only the literal underscore matches.
    assert len(rows) == 1
    assert rows[0].value == "a_b@example.com"


def test_get_normalizes_lookup_value(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    store.upsert(_record(type_="domain", value="example.com"))
    # Lookup with mixed case and trailing dot — same row.
    rec = store.get("domain", "EXAMPLE.COM.")
    assert rec is not None
    assert rec.value == "example.com"


def test_get_by_id(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id, _ = store.upsert(_record(value="a" * 64))
    rec = store.get_by_id(ioc_id)
    assert rec is not None
    assert rec.id == ioc_id
    assert store.get_by_id(99_999) is None


def test_tags_round_trip(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    store.upsert(_record(value="a" * 64, tags=("malware", "phishing")))
    rec = store.get("sha256", "a" * 64)
    assert rec is not None
    assert rec.tags == ("malware", "phishing")


def test_sources_for_returns_all(migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id, _ = store.upsert(_record(source="otx:default"))
    store.upsert(_record(source="vt:default"))
    sources = store.sources_for(ioc_id)
    assert len(sources) == 2


def test_get_default_store_smoke(tmp_root: object) -> None:
    """``get_default_store`` opens the canonical DB and applies migrations."""
    store = store_mod.get_default_store()
    try:
        assert store.count() == 0
    finally:
        store.database.close()
