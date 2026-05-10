"""AI bridge selector — picks the first healthy transport.

Per brief v3 §7: ship transports A (headless), B (MCP), C (clipboard).
Selector tries them in declared order, returning the first whose
``health_check()`` passes. The chosen transport is wrapped in
:class:`AuditingBridge` so every ``complete()`` call is logged.

Phase 4.1 wires A and C. Phase 4.3 adds B between them.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from secops_term.ai.audit import AuditingBridge
from secops_term.ai.bridge import AIBridge, AIBridgeError
from secops_term.core import audit as audit_mod


@dataclass(frozen=True)
class TransportCandidate:
    """A bridge plus the name to record against its audit entries."""

    bridge: AIBridge
    name: str


class NoTransportAvailable(AIBridgeError):
    """No candidate bridge passed its ``health_check()``."""


async def compose_bridge(
    candidates: Sequence[TransportCandidate],
    *,
    audit_logger: audit_mod.AuditLogger,
    debug_ai: bool = False,
) -> AuditingBridge:
    """Probe each candidate; return the first healthy one wrapped for audit.

    Order is significant — pass candidates in priority order
    (headless first, MCP second, clipboard last).

    Raises :class:`NoTransportAvailable` if none are healthy. Caller
    should surface this as a user-facing "AI features unavailable"
    message rather than a stack trace.
    """
    if not candidates:
        raise NoTransportAvailable("no transports configured")
    last_name = ""
    for candidate in candidates:
        last_name = candidate.name
        try:
            ok = await candidate.bridge.health_check()
        except Exception:
            ok = False
        if ok:
            return AuditingBridge(
                candidate.bridge,
                audit_logger=audit_logger,
                transport=candidate.name,
                debug_ai=debug_ai,
            )
    raise NoTransportAvailable(f"no AI transport is healthy (last tried: {last_name})")


__all__ = ["NoTransportAvailable", "TransportCandidate", "compose_bridge"]
