"""Hash-chained append-only audit log.

Per brief v3 §3.5.10:

- File ``~/.secops-term/audit.jsonl``, mode ``0o600`` / restricted ACL.
- Each line is a JSON object:
  ``{"seq": int, "ts": iso8601, "prev_hash": hex, "entry": {...}, "hash": hex}``.
- ``hash = sha256(prev_hash || canonical_json(entry))``.
  Genesis ``prev_hash`` is 64 zeros.
- Canonical JSON: keys sorted, no insignificant whitespace,
  ``ensure_ascii=False``, ``NaN``/``Infinity`` rejected.
- Rotation: 50 MB or daily, whichever first. Rotated file
  ``audit-YYYYMMDD-HHMMSS.jsonl``. Chain continues across rotation: new file's
  first ``prev_hash`` = last hash of previous file. Rotation itself is an
  audit entry of type ``rotation``.
- Probe entries get ``kind="probe"`` for filtering.
- Redaction at emit: entries pass through ``redact(entry)`` before hashing,
  so the trail is portable without leaking secrets.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secops_term.core import paths, redact

_AUDIT_FILENAME = "audit.jsonl"
GENESIS_HASH = "0" * 64
DEFAULT_ROTATION_SIZE_BYTES = 50 * 1024 * 1024


class AuditError(Exception):
    """Base class for audit errors."""


class ChainBroken(AuditError):
    """Hash-chain integrity check failed."""

    def __init__(self, file: Path, seq: int, ts: str, reason: str) -> None:
        super().__init__(f"chain break in {file} at seq={seq} ts={ts}: {reason}")
        self.file = file
        self.seq = seq
        self.ts = ts
        self.reason = reason


@dataclass(frozen=True)
class AuditEntry:
    """A single audit log entry as written to disk."""

    seq: int
    ts: str
    prev_hash: str
    entry: dict[str, Any]
    hash: str


def canonical_json(value: Any) -> str:
    """Canonical JSON: sorted keys, no whitespace, NaN/Infinity rejected."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _today_utc_date() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _compute_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    body = (prev_hash + canonical_json(entry)).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


class AuditLogger:
    """Append-only writer. Single instance per process."""

    def __init__(
        self,
        *,
        path: Path | None = None,
        rotation_size: int = DEFAULT_ROTATION_SIZE_BYTES,
    ) -> None:
        self._lock = threading.Lock()
        self._path = path if path is not None else _default_audit_path()
        self._rotation_size = rotation_size
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        self._loaded = False
        self._active_date: str | None = None

    @property
    def path(self) -> Path:
        return self._path

    def emit(self, entry: dict[str, Any]) -> AuditEntry:
        """Redact, hash, and append a single entry."""
        with self._lock:
            self._load_state()
            redacted = _redact_value(entry)
            self._maybe_rotate(approx_size=len(canonical_json(redacted)) + 256)
            return self._write_entry_unlocked(redacted)

    def _write_entry_unlocked(self, redacted: dict[str, Any]) -> AuditEntry:
        self._seq += 1
        seq = self._seq
        prev_hash = self._prev_hash
        ts = _now_iso()
        hash_ = _compute_hash(prev_hash, redacted)
        line = (
            canonical_json(
                {
                    "seq": seq,
                    "ts": ts,
                    "prev_hash": prev_hash,
                    "entry": redacted,
                    "hash": hash_,
                }
            )
            + "\n"
        )
        self._append_line(line)
        self._prev_hash = hash_
        if self._active_date is None:
            self._active_date = _today_utc_date()
        return AuditEntry(seq=seq, ts=ts, prev_hash=prev_hash, entry=redacted, hash=hash_)

    def _load_state(self) -> None:
        if self._loaded:
            return
        if not self._path.exists():
            self._loaded = True
            return
        paths.verify_restrictive_acl(self._path)
        last: AuditEntry | None = None
        first_ts: str | None = None
        for entry in _iter_entries(self._path):
            if first_ts is None:
                first_ts = entry.ts
            last = entry
        if last is not None:
            self._seq = last.seq
            self._prev_hash = last.hash
        if first_ts is not None:
            self._active_date = first_ts[:10]
        self._loaded = True

    def _append_line(self, line: str) -> None:
        new_file = not self._path.exists()
        if new_file:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(self._path, flags, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)
            paths.apply_restrictive_acl(self._path)
            return
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(line)

    def _maybe_rotate(self, approx_size: int) -> None:
        if not self._path.exists():
            return
        cur_size = self._path.stat().st_size
        today = _today_utc_date()
        size_trip = cur_size + approx_size > self._rotation_size
        date_trip = self._active_date is not None and self._active_date != today
        if not (size_trip or date_trip):
            return
        reason = "size" if size_trip else "daily"
        rotation_entry = {
            "kind": "rotation",
            "reason": reason,
            "from_size": cur_size,
        }
        self._write_entry_unlocked(rotation_entry)
        # Microsecond precision so rotations within the same second don't
        # collide and overwrite each other via os.replace.
        ts_compact = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
        rotated = self._path.with_name(f"audit-{ts_compact}.jsonl")
        os.replace(self._path, rotated)
        self._active_date = today


def _redact_value(value: Any) -> Any:
    """Recursively pass every str leaf through the redactor."""
    if isinstance(value, str):
        return redact.redact(value)
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(v) for v in value]
    return value


def _iter_entries(path: Path) -> Iterator[AuditEntry]:
    """Yield :class:`AuditEntry` for each line in ``path``. No chain validation."""
    with open(path, encoding="utf-8") as fh:
        for raw_line in fh:
            raw = raw_line.rstrip("\n")
            if not raw:
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ChainBroken(path, -1, "?", f"line is not valid JSON: {exc.msg}") from exc
            try:
                yield AuditEntry(
                    seq=payload["seq"],
                    ts=payload["ts"],
                    prev_hash=payload["prev_hash"],
                    entry=payload["entry"],
                    hash=payload["hash"],
                )
            except KeyError as exc:
                raise ChainBroken(
                    path, -1, "?", f"line missing required field: {exc.args[0]}"
                ) from exc


def verify_chain(*, root: Path | None = None) -> tuple[int, int]:
    """Walk every audit file in ``root``, verify the chain.

    Returns ``(files_checked, entries_checked)``. Raises :class:`ChainBroken`
    on first break.
    """
    root_path = root if root is not None else paths.get_root()
    files = _ordered_audit_files(root_path)
    files_checked = 0
    entries_checked = 0
    expected_prev = GENESIS_HASH
    expected_seq = 0
    for path in files:
        files_checked += 1
        for entry in _iter_entries(path):
            expected_seq += 1
            if entry.seq != expected_seq:
                raise ChainBroken(path, entry.seq, entry.ts, f"expected seq={expected_seq}")
            if entry.prev_hash != expected_prev:
                raise ChainBroken(
                    path,
                    entry.seq,
                    entry.ts,
                    f"prev_hash mismatch (expected {expected_prev[:12]}…)",
                )
            recomputed = _compute_hash(entry.prev_hash, entry.entry)
            if entry.hash != recomputed:
                raise ChainBroken(path, entry.seq, entry.ts, "hash does not match entry contents")
            expected_prev = entry.hash
            entries_checked += 1
    return files_checked, entries_checked


def _ordered_audit_files(root: Path) -> list[Path]:
    """List rotated ``audit-*.jsonl`` files chronologically, then the active file."""
    rotated = sorted(root.glob("audit-*.jsonl"))
    active = root / _AUDIT_FILENAME
    out: list[Path] = list(rotated)
    if active.exists():
        out.append(active)
    return out


def _default_audit_path() -> Path:
    return paths.safe_join(paths.get_root(), _AUDIT_FILENAME)
