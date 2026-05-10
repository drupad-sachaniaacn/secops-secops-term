"""Tainted-string registry and redaction.

Every secret loaded from keyring or the encrypted-file fallback is registered
here via ``taint(value, label)``. Audit log entries and crash tracebacks both
pass through ``redact(text)`` before they are written or displayed, replacing
every tainted occurrence with ``<redacted:label>``.

The registry is in-memory only. It is never serialized, never logged, and
never persisted. ``__repr__`` deliberately returns only a count so accidental
debug-print never leaks contents.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class _Tainted:
    value: str
    label: str


class SecretRegistry:
    """Registry of tainted strings used by redactors.

    Use the module-level singleton via :func:`taint` and :func:`redact`.
    A fresh instance can be constructed for tests.
    """

    _MIN_USEFUL_LEN = 4

    def __init__(self) -> None:
        self._items: list[_Tainted] = []
        self._lock = threading.Lock()

    def taint(self, value: str, label: str) -> None:
        """Register ``value`` with ``label``. Idempotent. Empty values ignored.

        Raises :class:`ValueError` if ``value`` is shorter than 4 chars: short
        values risk redacting unrelated substrings in arbitrary text.
        """
        if not value:
            return
        if len(value) < self._MIN_USEFUL_LEN:
            raise ValueError(
                f"refusing to taint string shorter than {self._MIN_USEFUL_LEN} "
                f"chars; label={label!r}"
            )
        with self._lock:
            for existing in self._items:
                if existing.value == value:
                    return
            self._items.append(_Tainted(value=value, label=label))

    def clear(self) -> None:
        """Drop all tainted entries. Used by tests."""
        with self._lock:
            self._items.clear()

    def redact(self, text: str) -> str:
        """Return ``text`` with every tainted occurrence replaced."""
        if not text:
            return text
        with self._lock:
            ordered = sorted(self._items, key=lambda t: len(t.value), reverse=True)
        out = text
        for entry in ordered:
            if entry.value in out:
                out = out.replace(entry.value, f"<redacted:{entry.label}>")
        return out

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def __repr__(self) -> str:
        with self._lock:
            return f"SecretRegistry(<{len(self._items)} entries>)"


_global = SecretRegistry()


def taint(value: str, label: str) -> None:
    """Module-level convenience: register a secret with the global registry."""
    _global.taint(value, label)


def redact(text: str) -> str:
    """Module-level convenience: redact text using the global registry."""
    return _global.redact(text)


def get_registry() -> SecretRegistry:
    """Return the module-level global registry. Useful for tests."""
    return _global
