"""MCP server (Transport B) — exposes SecOps Terminal tools to Claude.

Per brief v3 §3.5.9 + §7.2:

- Loopback-only HTTP listener (127.0.0.1 / ::1).
- Optional bearer-token auth from keyring.
- Per-tool rate limiting (default 60 calls / minute).
- Every tool call audited with ``kind="mcp_tool_call"``.

Exposed tools (per brief §7.2): ``search_iocs``, ``run_retro_hunt``,
``summarize_alert``, ``nl_to_udm``, ``nl_to_v1``.

Pure logic (the tool functions) lives in :mod:`secops_term.mcp.tools`;
auth + rate-limit middleware lives in :mod:`secops_term.mcp.gate`; the
FastMCP wire-protocol wrapper lives in :mod:`secops_term.mcp.server`.
"""

from __future__ import annotations

from secops_term.mcp.gate import (
    GateError,
    RateLimited,
    RateLimiter,
    Unauthorized,
    check_bearer_token,
)
from secops_term.mcp.tools import (
    MCP_TOOLS,
    ToolError,
    ToolHandler,
    ToolSpec,
)

__all__ = [
    "MCP_TOOLS",
    "GateError",
    "RateLimited",
    "RateLimiter",
    "ToolError",
    "ToolHandler",
    "ToolSpec",
    "Unauthorized",
    "check_bearer_token",
]
