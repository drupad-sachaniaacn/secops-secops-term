"""Database open hardening + migration runner."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from secops_term.core import db


def test_open_creates_file_with_restrictive_acl(tmp_root: Path) -> None:
    database = db.Database(path=tmp_root / "secops-term.db")
    conn = database.open()
    assert (tmp_root / "secops-term.db").exists()
    if os.name != "nt":
        mode = (tmp_root / "secops-term.db").stat().st_mode & 0o777
        assert mode == 0o600
    # Sanity: connection is usable.
    conn.execute("CREATE TABLE t (x INTEGER)")
    conn.execute("INSERT INTO t (x) VALUES (?)", (1,))
    rows = conn.execute("SELECT x FROM t").fetchall()
    assert [r["x"] for r in rows] == [1]
    database.close()


def test_pragmas_are_set(tmp_root: Path) -> None:
    database = db.Database(path=tmp_root / "secops-term.db")
    conn = database.open()
    journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
    secure_delete = conn.execute("PRAGMA secure_delete").fetchone()[0]
    foreign_keys = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    synchronous = conn.execute("PRAGMA synchronous").fetchone()[0]
    assert journal.lower() == "wal"
    assert int(secure_delete) == 1
    assert int(foreign_keys) == 1
    assert int(synchronous) == 2  # FULL
    database.close()


def test_meta_table_created(tmp_root: Path) -> None:
    database = db.Database(path=tmp_root / "secops-term.db")
    conn = database.open()
    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "schema_migrations" in tables
    database.close()


def test_apply_migrations_in_order(tmp_root: Path) -> None:
    database = db.Database(path=tmp_root / "secops-term.db")
    migrations = [
        db.Migration(version=2, name="b", sql="CREATE TABLE b (x INTEGER);"),
        db.Migration(version=1, name="a", sql="CREATE TABLE a (x INTEGER);"),
    ]
    applied = database.apply_migrations(migrations)
    assert applied == 2
    conn = database.open()
    versions = sorted(database.applied_versions())
    assert versions == [1, 2]
    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert {"a", "b"}.issubset(tables)
    database.close()


def test_apply_migrations_idempotent(tmp_root: Path) -> None:
    database = db.Database(path=tmp_root / "secops-term.db")
    migrations = [db.Migration(version=1, name="a", sql="CREATE TABLE a (x INTEGER);")]
    assert database.apply_migrations(migrations) == 1
    assert database.apply_migrations(migrations) == 0
    database.close()


def test_migration_failure_rolls_back(tmp_root: Path) -> None:
    database = db.Database(path=tmp_root / "secops-term.db")
    migrations = [
        db.Migration(version=1, name="ok", sql="CREATE TABLE ok (x INTEGER);"),
        db.Migration(version=2, name="bad", sql="CREATE TABLE bad (x INTEGER); GIBBERISH SQL;"),
    ]
    with pytest.raises(sqlite3.OperationalError):
        database.apply_migrations(migrations)
    # Migration 1 committed; migration 2 rolled back.
    assert database.applied_versions() == {1}
    conn = database.open()
    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "ok" in tables
    assert "bad" not in tables
    database.close()


def test_discover_migrations_returns_list() -> None:
    # Phase 0 ships no concrete migrations; the function returns an empty list
    # rather than raising.
    out = db.discover_migrations()
    assert isinstance(out, list)


def test_discover_rejects_bad_filename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Synthetic test: a malformed filename in the migrations package raises."""
    fake_pkg = tmp_path / "fake_migs"
    fake_pkg.mkdir()
    (fake_pkg / "__init__.py").write_text("")
    (fake_pkg / "abc_bad.sql").write_text("SELECT 1;")

    import importlib
    import sys

    sys.path.insert(0, str(tmp_path))
    try:
        importlib.import_module("fake_migs")
        monkeypatch.setattr(db, "_MIGRATIONS_PACKAGE", "fake_migs")
        with pytest.raises(db.DBError):
            db.discover_migrations()
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("fake_migs", None)
