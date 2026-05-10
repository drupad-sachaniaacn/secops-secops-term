"""SQLite layer: hardened pragmas, ACL-checked open, parameterized queries only.

Per brief v3 §3.5.5:

- Single connection per process. WAL mode.
- ``PRAGMA secure_delete=ON``, ``PRAGMA foreign_keys=ON``, ``synchronous=FULL``.
- File mode ``0o600`` (POSIX) / restricted ACL (Windows). Verified on open.
- Migrations: checked-in SQL files in
  ``secops_term/core/migrations/``, run in order. No string-formatted DDL.
- All non-DDL SQL must be parameterized (enforced by ruff S608).
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from secops_term.core import paths

_DB_FILENAME = "secops-term.db"
_MIGRATIONS_PACKAGE = "secops_term.core.migrations"


class DBError(Exception):
    """Base class for DB errors."""


@dataclass(frozen=True)
class Migration:
    """A single migration file."""

    version: int
    name: str
    sql: str


class Database:
    """Wraps the single per-process ``sqlite3.Connection``."""

    def __init__(self, *, path: Path | None = None) -> None:
        self._lock = threading.RLock()
        self._path = path if path is not None else _default_db_path()
        self._conn: sqlite3.Connection | None = None

    @property
    def path(self) -> Path:
        return self._path

    def open(self) -> sqlite3.Connection:
        with self._lock:
            if self._conn is not None:
                return self._conn
            new_file = not self._path.exists()
            if not new_file:
                paths.verify_restrictive_acl(self._path)
            else:
                paths.ensure_root_initialized()
            conn = sqlite3.connect(
                str(self._path),
                isolation_level=None,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA secure_delete=ON")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            if new_file:
                paths.apply_restrictive_acl(self._path)
            self._conn = conn
            self._init_meta_unlocked()
            return conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _init_meta_unlocked(self) -> None:
        if self._conn is None:
            raise DBError("connection not open")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

    def applied_versions(self) -> set[int]:
        conn = self.open()
        rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
        return {int(row["version"]) for row in rows}

    def apply_migrations(self, migrations: Iterable[Migration]) -> int:
        """Apply pending migrations in version order. Returns count applied.

        Each migration's SQL is split on ``;`` and executed statement-by-statement
        inside a manual ``BEGIN``/``COMMIT`` so a partial failure rolls back the
        whole migration. ``executescript`` is deliberately avoided because in
        Python's sqlite3 it issues an implicit ``COMMIT`` first, which would
        terminate our transaction.
        """
        conn = self.open()
        applied = self.applied_versions()
        ordered = sorted(migrations, key=lambda m: m.version)
        count = 0
        for m in ordered:
            if m.version in applied:
                continue
            statements = _split_sql_statements(m.sql)
            conn.execute("BEGIN")
            try:
                for stmt in statements:
                    conn.execute(stmt)
                conn.execute(
                    "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
                    (m.version, m.name),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            count += 1
        return count


def discover_migrations() -> list[Migration]:
    """Load migrations from the ``secops_term.core.migrations`` package.

    Filename format: ``NNN_short_name.sql`` where ``NNN`` is the integer
    version (e.g. ``001_initial.sql``).
    """
    out: list[Migration] = []
    try:
        files = resources.files(_MIGRATIONS_PACKAGE)
    except (ModuleNotFoundError, FileNotFoundError):
        return out
    for entry in files.iterdir():
        if not entry.is_file():
            continue
        name = entry.name
        if not name.endswith(".sql"):
            continue
        stem = Path(name).stem
        version_str, _, mig_name = stem.partition("_")
        try:
            version = int(version_str)
        except ValueError as exc:
            raise DBError(f"migration file has bad version prefix: {name}") from exc
        sql = entry.read_text(encoding="utf-8")
        out.append(Migration(version=version, name=mig_name or stem, sql=sql))
    return out


def _default_db_path() -> Path:
    return paths.safe_join(paths.get_root(), _DB_FILENAME)


def _split_sql_statements(sql: str) -> list[str]:
    """Split a migration SQL blob on ``;`` boundaries.

    Strips ``-- ...`` line comments and ignores empty fragments. Migration
    files are author-controlled and must not embed ``;`` inside string
    literals — if a future migration needs that, switch to a real SQL parser
    (sqlglot) rather than expanding this splitter.
    """
    cleaned_lines: list[str] = []
    for line in sql.splitlines():
        idx = line.find("--")
        if idx >= 0:
            line = line[:idx]
        cleaned_lines.append(line)
    blob = "\n".join(cleaned_lines)
    statements: list[str] = []
    for fragment in blob.split(";"):
        stmt = fragment.strip()
        if stmt:
            statements.append(stmt)
    return statements
