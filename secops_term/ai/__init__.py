"""AI bridge — Claude Code headless / MCP server / clipboard fallback.

See brief v3 §7 (transports) and §3.5.8 (subprocess hardening).
Phase 0 shipped Transport A (:class:`HeadlessClaudeBridge`) plus the
:class:`AIBridge` Protocol and the sentinel-fenced :func:`wrap_untrusted`.
Phase 4.1 ships:

- :class:`AuditingBridge` — audit-logging decorator for any transport.
- :class:`ClipboardBridge` — Transport C.
- :func:`compose_bridge` — selector that picks the first healthy transport.

Phase 4.2 adds the NLP query helper. Phase 4.3 adds Transport B (MCP server).
"""

from __future__ import annotations

from secops_term.ai.audit import AuditingBridge
from secops_term.ai.bridge import (
    AIBridge,
    AIBridgeError,
    ClaudeCaptureExceeded,
    ClaudeFailed,
    ClaudeNotFound,
    ClaudeResult,
    ClaudeTimeout,
    HeadlessClaudeBridge,
    build_subprocess_env,
    resolve_claude_path,
    wrap_untrusted,
)
from secops_term.ai.clipboard import (
    ClipboardBridge,
    ClipboardUnavailable,
    ResponseProvider,
)
from secops_term.ai.nlp_prompts import QueryTarget, render_prompt
from secops_term.ai.nlp_query import GeneratedQuery, generate_query
from secops_term.ai.nlp_validators import ValidationResult, validate_query
from secops_term.ai.selector import (
    NoTransportAvailable,
    TransportCandidate,
    compose_bridge,
)

__all__ = [
    "AIBridge",
    "AIBridgeError",
    "AuditingBridge",
    "ClaudeCaptureExceeded",
    "ClaudeFailed",
    "ClaudeNotFound",
    "ClaudeResult",
    "ClaudeTimeout",
    "ClipboardBridge",
    "ClipboardUnavailable",
    "GeneratedQuery",
    "HeadlessClaudeBridge",
    "NoTransportAvailable",
    "QueryTarget",
    "ResponseProvider",
    "TransportCandidate",
    "ValidationResult",
    "build_subprocess_env",
    "compose_bridge",
    "generate_query",
    "render_prompt",
    "resolve_claude_path",
    "validate_query",
    "wrap_untrusted",
]
