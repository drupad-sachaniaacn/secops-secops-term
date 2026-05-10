"""SQLite-backed IOC store.

Wraps the ``iocs``, ``ioc_sources``, and ``retro_hunt_jobs`` tables (per
brief v3 §6.1). :class:`IntelRecord` flows in from concrete provider
implementations, gets normalized via :func:`secops_term.intel.ioc.normalize_value`,
and dedupes on ``UNIQUE(type, value)``.

:meth:`IOCStore.upsert` returns ``(ioc_id, is_new_observation)`` so callers
(the playbook engine in Phase 5) can enqueue retro-hunt jobs only for
genuinely new IOCs, not for re-observations.

Retro-hunt jobs (Phase 2.2):

- :meth:`enqueue_retro_hunt` — insert a ``queued`` job for one IOC + platform.
- :meth:`next_pending_job` — atomically claim the oldest queued job
  (transactionally moves it to ``running``).
- :meth:`complete_job` / :meth:`fail_job` — terminal state transitions.
- :meth:`get_job` / :meth:`recent_jobs` — read-only queries.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from secops_term.core import db as core_db
from secops_term.intel import ioc as ioc_mod
from secops_term.intel.providers.base import IntelRecord

# Retro-hunt job status values.
JOB_QUEUED = "queued"
JOB_RUNNING = "running"
JOB_DONE = "done"
JOB_ERROR = "error"
_JOB_STATUSES = frozenset({JOB_QUEUED, JOB_RUNNING, JOB_DONE, JOB_ERROR})

_ERROR_MESSAGE_LIMIT = 2000


@dataclass(frozen=True)
class RetroHuntJob:
    """One row from the ``retro_hunt_jobs`` table."""

    id: int
    ioc_id: int
    platform: str
    status: str  # queued | running | done | error
    query: str | None
    hits: int | None
    created_at: datetime
    completed_at: datetime | None
    error: str | None


class IOCStoreError(Exception):
    """Base class for IOC store errors."""


class IOCStore:
    """High-level wrapper around the IOC tables in the SQLite store."""

    def __init__(self, database: core_db.Database) -> None:
        self._db = database

    @property
    def database(self) -> core_db.Database:
        return self._db

    # Writes

    def upsert(self, record: IntelRecord) -> tuple[int, bool]:
        """Insert or update one :class:`IntelRecord`.

        Returns ``(ioc_id, is_new)`` — ``is_new=True`` only on first
        observation of the (type, value) pair.

        Always appends a row to ``ioc_sources``, so re-observations from
        different providers are preserved.
        """
        normalized = ioc_mod.normalize_value(record.type, record.value)
        fetched_iso = _to_iso(record.fetched_at)
        tags_json = json.dumps(list(record.tags))
        conn = self._db.open()

        row = conn.execute(
            "SELECT id FROM iocs WHERE type = ? AND value = ?",
            (record.type, normalized),
        ).fetchone()

        if row is None:
            cur = conn.execute(
                "INSERT INTO iocs (type, value, first_seen, last_seen, "
                "confidence, tags) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    record.type,
                    normalized,
                    fetched_iso,
                    fetched_iso,
                    record.confidence,
                    tags_json,
                ),
            )
            last_id = cur.lastrowid
            if last_id is None:  # pragma: no cover - INSERT always assigns rowid
                raise IOCStoreError("INSERT did not assign a rowid")
            ioc_id = int(last_id)
            is_new = True
        else:
            ioc_id = int(row["id"])
            conn.execute(
                "UPDATE iocs SET last_seen = ?, "
                "confidence = COALESCE(?, confidence), tags = ? "
                "WHERE id = ?",
                (fetched_iso, record.confidence, tags_json, ioc_id),
            )
            is_new = False

        conn.execute(
            "INSERT INTO ioc_sources (ioc_id, source, source_ref, context, "
            "fetched_at) VALUES (?, ?, ?, ?, ?)",
            (
                ioc_id,
                record.source,
                record.source_ref,
                record.context,
                fetched_iso,
            ),
        )
        return ioc_id, is_new

    def bulk_upsert(self, records: Iterable[IntelRecord]) -> list[tuple[int, bool]]:
        """Upsert many records. Returns one ``(ioc_id, is_new)`` per record."""
        return [self.upsert(r) for r in records]

    # Reads

    def get(self, type_: str, value: str) -> ioc_mod.IOC | None:
        """Look up an IOC by type and value (value is normalized first)."""
        normalized = ioc_mod.normalize_value(type_, value)
        conn = self._db.open()
        row = conn.execute(
            "SELECT * FROM iocs WHERE type = ? AND value = ?",
            (type_, normalized),
        ).fetchone()
        return _row_to_ioc(row) if row is not None else None

    def get_by_id(self, ioc_id: int) -> ioc_mod.IOC | None:
        conn = self._db.open()
        row = conn.execute("SELECT * FROM iocs WHERE id = ?", (ioc_id,)).fetchone()
        return _row_to_ioc(row) if row is not None else None

    def find(
        self,
        *,
        type_: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ioc_mod.IOC]:
        """List IOCs, newest first.

        Filters: ``type_`` (exact match), ``since`` (last_seen >=).
        ``limit`` is bounded to ``[1, 10000]`` to prevent runaway queries.

        Named ``find`` rather than ``list`` because the latter would shadow
        the ``list`` builtin in this class's scope under
        ``from __future__ import annotations``.
        """
        if limit < 1 or limit > 10_000:
            raise IOCStoreError(f"limit must be in [1, 10000], got {limit}")
        if offset < 0:
            raise IOCStoreError(f"offset must be non-negative, got {offset}")
        if type_ is not None and type_ not in ioc_mod.KNOWN_TYPES:
            raise IOCStoreError(f"unknown IOC type: {type_!r}")

        conn = self._db.open()
        clauses: list[str] = []
        params: list[Any] = []
        if type_ is not None:
            clauses.append("type = ?")
            params.append(type_)
        if since is not None:
            clauses.append("last_seen >= ?")
            params.append(_to_iso(since))
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        # Composition uses only constant column names; user values are bound
        # via `?` placeholders below — safe despite ruff S608.
        sql = "SELECT * FROM iocs " + where_sql + " ORDER BY last_seen DESC LIMIT ? OFFSET ?"  # noqa: S608
        rows = conn.execute(sql, (*params, limit, offset)).fetchall()
        return [_row_to_ioc(r) for r in rows]

    def count(self, *, type_: str | None = None) -> int:
        if type_ is not None and type_ not in ioc_mod.KNOWN_TYPES:
            raise IOCStoreError(f"unknown IOC type: {type_!r}")
        conn = self._db.open()
        if type_ is None:
            row = conn.execute("SELECT COUNT(*) AS n FROM iocs").fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) AS n FROM iocs WHERE type = ?", (type_,)).fetchone()
        return int(row["n"])

    def search(self, query: str, *, limit: int = 100) -> list[ioc_mod.IOC]:
        """Substring match on ``value`` (case-insensitive, ASCII).

        Empty / whitespace-only queries return ``[]``. ``limit`` is bounded
        to ``[1, 10000]``.
        """
        if not query.strip():
            return []
        if limit < 1 or limit > 10_000:
            raise IOCStoreError(f"limit must be in [1, 10000], got {limit}")
        conn = self._db.open()
        # Escape LIKE meta-characters so a user query containing `%` or `_`
        # matches literally rather than as a wildcard.
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = conn.execute(
            "SELECT * FROM iocs WHERE value LIKE ? ESCAPE '\\' ORDER BY last_seen DESC LIMIT ?",
            (f"%{escaped}%", limit),
        ).fetchall()
        return [_row_to_ioc(r) for r in rows]

    def sources_for(self, ioc_id: int) -> list[ioc_mod.IocSource]:
        """Every source observation for one IOC, newest first."""
        conn = self._db.open()
        rows = conn.execute(
            "SELECT * FROM ioc_sources WHERE ioc_id = ? ORDER BY fetched_at DESC",
            (ioc_id,),
        ).fetchall()
        return [_row_to_source(r) for r in rows]

    # Retro-hunt jobs

    def enqueue_retro_hunt(self, ioc_id: int, platform: str) -> int:
        """Insert a ``queued`` retro_hunt_job. Returns the new job id."""
        if not platform:
            raise IOCStoreError("platform must be non-empty")
        conn = self._db.open()
        cur = conn.execute(
            "INSERT INTO retro_hunt_jobs (ioc_id, platform, status, created_at) "
            "VALUES (?, ?, ?, ?)",
            (ioc_id, platform, JOB_QUEUED, _to_iso(datetime.now(UTC))),
        )
        last = cur.lastrowid
        if last is None:  # pragma: no cover - INSERT always assigns rowid
            raise IOCStoreError("INSERT did not assign a rowid")
        return int(last)

    def next_pending_job(self, platform: str) -> RetroHuntJob | None:
        """Atomically claim the oldest ``queued`` job for ``platform``.

        Transactionally moves the job to ``running`` so a follow-up worker
        run won't pick it up. Returns ``None`` if no jobs are queued.
        """
        if not platform:
            raise IOCStoreError("platform must be non-empty")
        conn = self._db.open()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT * FROM retro_hunt_jobs "
                "WHERE platform = ? AND status = ? "
                "ORDER BY created_at LIMIT 1",
                (platform, JOB_QUEUED),
            ).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return None
            job_id = int(row["id"])
            conn.execute(
                "UPDATE retro_hunt_jobs SET status = ? WHERE id = ?",
                (JOB_RUNNING, job_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        # Re-build the dataclass with the running status (the row we
        # selected was still queued).
        return RetroHuntJob(
            id=job_id,
            ioc_id=int(row["ioc_id"]),
            platform=str(row["platform"]),
            status=JOB_RUNNING,
            query=row["query"],
            hits=int(row["hits"]) if row["hits"] is not None else None,
            created_at=_from_iso(row["created_at"]),
            completed_at=_from_iso(row["completed_at"]) if row["completed_at"] else None,
            error=row["error"],
        )

    def complete_job(self, job_id: int, *, hits: int, query: str) -> None:
        """Mark a job ``done`` with hit count and the executed query."""
        if hits < 0:
            raise IOCStoreError(f"hits must be >= 0, got {hits}")
        conn = self._db.open()
        conn.execute(
            "UPDATE retro_hunt_jobs SET status = ?, hits = ?, query = ?, "
            "completed_at = ?, error = NULL WHERE id = ?",
            (
                JOB_DONE,
                hits,
                query,
                _to_iso(datetime.now(UTC)),
                job_id,
            ),
        )

    def fail_job(self, job_id: int, error: str) -> None:
        """Mark a job ``error`` with a truncated error message."""
        conn = self._db.open()
        conn.execute(
            "UPDATE retro_hunt_jobs SET status = ?, completed_at = ?, error = ? WHERE id = ?",
            (
                JOB_ERROR,
                _to_iso(datetime.now(UTC)),
                error[:_ERROR_MESSAGE_LIMIT],
                job_id,
            ),
        )

    def get_job(self, job_id: int) -> RetroHuntJob | None:
        conn = self._db.open()
        row = conn.execute("SELECT * FROM retro_hunt_jobs WHERE id = ?", (job_id,)).fetchone()
        return _row_to_job(row) if row is not None else None

    def recent_jobs(
        self,
        *,
        platform: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[RetroHuntJob]:
        """Newest jobs first, optionally filtered by platform / status."""
        if limit < 1 or limit > 10_000:
            raise IOCStoreError(f"limit must be in [1, 10000], got {limit}")
        if status is not None and status not in _JOB_STATUSES:
            raise IOCStoreError(f"unknown status: {status!r}")
        clauses: list[str] = []
        params: list[Any] = []
        if platform is not None:
            clauses.append("platform = ?")
            params.append(platform)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        # Composition uses only constant column names; user values are bound
        # via `?` placeholders below — safe despite ruff S608.
        sql = "SELECT * FROM retro_hunt_jobs " + where + " ORDER BY created_at DESC LIMIT ?"  # noqa: S608
        conn = self._db.open()
        rows = conn.execute(sql, (*params, limit)).fetchall()
        return [_row_to_job(r) for r in rows]

    def jobs_for_ioc(self, ioc_id: int) -> list[RetroHuntJob]:
        """Every retro-hunt job for one IOC, newest first."""
        conn = self._db.open()
        rows = conn.execute(
            "SELECT * FROM retro_hunt_jobs WHERE ioc_id = ? ORDER BY created_at DESC",
            (ioc_id,),
        ).fetchall()
        return [_row_to_job(r) for r in rows]


def get_default_store() -> IOCStore:
    """Open the default :class:`Database`, apply migrations, return an :class:`IOCStore`."""
    database = core_db.Database()
    database.apply_migrations(core_db.discover_migrations())
    return IOCStore(database)


# ISO8601 helpers — the audit log already uses the same shape.


def _to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _from_iso(s: str) -> datetime:
    text = s
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _row_to_ioc(row: sqlite3.Row) -> ioc_mod.IOC:
    tags_raw = row["tags"]
    tags: tuple[str, ...]
    if tags_raw:
        try:
            decoded = json.loads(tags_raw)
            tags = tuple(str(t) for t in decoded)
        except (json.JSONDecodeError, TypeError):
            tags = ()
    else:
        tags = ()
    confidence = row["confidence"]
    return ioc_mod.IOC(
        id=int(row["id"]),
        type=str(row["type"]),
        value=str(row["value"]),
        first_seen=_from_iso(row["first_seen"]),
        last_seen=_from_iso(row["last_seen"]),
        confidence=int(confidence) if confidence is not None else None,
        tags=tags,
    )


def _row_to_source(row: sqlite3.Row) -> ioc_mod.IocSource:
    return ioc_mod.IocSource(
        ioc_id=int(row["ioc_id"]),
        source=str(row["source"]),
        source_ref=row["source_ref"],
        context=row["context"],
        fetched_at=_from_iso(row["fetched_at"]),
    )


def _row_to_job(row: sqlite3.Row) -> RetroHuntJob:
    completed_raw = row["completed_at"]
    return RetroHuntJob(
        id=int(row["id"]),
        ioc_id=int(row["ioc_id"]),
        platform=str(row["platform"]),
        status=str(row["status"]),
        query=row["query"],
        hits=int(row["hits"]) if row["hits"] is not None else None,
        created_at=_from_iso(row["created_at"]),
        completed_at=_from_iso(completed_raw) if completed_raw else None,
        error=row["error"],
    )
