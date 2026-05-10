"""Audit logging wrapper for AI bridge calls.

Per brief v3 §7.5 last paragraph: every AI call emits an audit entry with
prompt hash, transport, latency, response hash, and untrusted-input count.
Full prompt/response only with ``--debug-ai``.

The wrapper is decoupled from concrete transports so each transport
(:class:`HeadlessClaudeBridge`, :class:`ClipboardBridge`, future MCP)
stays focused on its mechanics — audit policy lives here, applied once
at the outer layer where the user-facing call lands.
"""

from __future__ import annotations

import contextlib
import hashlib
from time import perf_counter
from typing import Any

from secops_term.ai.bridge import AIBridge
from secops_term.core import audit as audit_mod


def _hash_text(text: str) -> str:
    """Short sha256 prefix — enough to spot changes, never enough to leak."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


class AuditingBridge:
    """Decorate an :class:`AIBridge` so every ``complete()`` call is audited.

    Emits a ``kind="ai_call"`` entry with::

        {
            "kind": "ai_call",
            "transport": "<name>",
            "prompt_hash": "<16 hex>",
            "response_hash": "<16 hex>",
            "untrusted_count": int,
            "latency_ms": float,
            "ok": bool,
            # only when constructed with debug_ai=True:
            "prompt": "...",
            "response": "...",
            # only on failure:
            "error": "<exception class>: <message tail>",
        }

    Audit emission is best-effort — a logger blow-up never breaks the
    AI call path (``contextlib.suppress(Exception)``).
    """

    def __init__(
        self,
        inner: AIBridge,
        *,
        audit_logger: audit_mod.AuditLogger,
        transport: str,
        debug_ai: bool = False,
    ) -> None:
        self._inner = inner
        self._audit = audit_logger
        self._transport = transport
        self._debug_ai = debug_ai

    @property
    def transport(self) -> str:
        return self._transport

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        untrusted_inputs: list[str] | None = None,
    ) -> str:
        start = perf_counter()
        prompt_hash = _hash_text(_canon_prompt(prompt, system, untrusted_inputs))
        untrusted_count = len(untrusted_inputs) if untrusted_inputs else 0
        try:
            response = await self._inner.complete(
                prompt, system=system, untrusted_inputs=untrusted_inputs
            )
        except Exception as exc:
            elapsed_ms = (perf_counter() - start) * 1000.0
            self._emit_failure(
                prompt_hash=prompt_hash,
                untrusted_count=untrusted_count,
                latency_ms=elapsed_ms,
                error=f"{type(exc).__name__}: {str(exc)[:200]}",
                prompt=prompt if self._debug_ai else None,
            )
            raise
        elapsed_ms = (perf_counter() - start) * 1000.0
        self._emit_success(
            prompt_hash=prompt_hash,
            response_hash=_hash_text(response),
            untrusted_count=untrusted_count,
            latency_ms=elapsed_ms,
            prompt=prompt if self._debug_ai else None,
            response=response if self._debug_ai else None,
        )
        return response

    async def health_check(self) -> bool:
        # Don't audit health checks — brief §3.5.10 reserves "probe" for
        # those, but health_check on the bridge is bookkeeping the
        # selector does, not a user-initiated AI call.
        return await self._inner.health_check()

    def _emit_success(
        self,
        *,
        prompt_hash: str,
        response_hash: str,
        untrusted_count: int,
        latency_ms: float,
        prompt: str | None,
        response: str | None,
    ) -> None:
        entry: dict[str, Any] = {
            "kind": "ai_call",
            "transport": self._transport,
            "prompt_hash": prompt_hash,
            "response_hash": response_hash,
            "untrusted_count": untrusted_count,
            "latency_ms": round(latency_ms, 3),
            "ok": True,
        }
        if prompt is not None:
            entry["prompt"] = prompt
        if response is not None:
            entry["response"] = response
        with contextlib.suppress(Exception):
            self._audit.emit(entry)

    def _emit_failure(
        self,
        *,
        prompt_hash: str,
        untrusted_count: int,
        latency_ms: float,
        error: str,
        prompt: str | None,
    ) -> None:
        entry: dict[str, Any] = {
            "kind": "ai_call",
            "transport": self._transport,
            "prompt_hash": prompt_hash,
            "untrusted_count": untrusted_count,
            "latency_ms": round(latency_ms, 3),
            "ok": False,
            "error": error,
        }
        if prompt is not None:
            entry["prompt"] = prompt
        with contextlib.suppress(Exception):
            self._audit.emit(entry)


def _canon_prompt(prompt: str, system: str | None, untrusted: list[str] | None) -> str:
    """Canonical hash input — same shape across calls so the hash is stable."""
    parts = []
    if system is not None:
        parts.append(f"sys:{system}")
    if untrusted:
        for i, u in enumerate(untrusted):
            parts.append(f"u{i}:{u}")
    parts.append(f"p:{prompt}")
    return "\n".join(parts)


__all__ = ["AuditingBridge"]
