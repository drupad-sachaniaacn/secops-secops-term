"""MCP wire-protocol wrapper — FastMCP-based loopback server.

Composes the pure-logic tool functions (:mod:`.tools`) with the auth +
rate-limit middleware (:mod:`.gate`) and exposes them as MCP tools
that Claude Code's chat client can call.

Per brief v3 §3.5.9:

- Bind ``127.0.0.1`` only (or ``::1``); refuse non-loopback hosts.
- Optional bearer-token auth from keyring.
- Per-tool rate limiting (default 60/min).
- Every tool call → audit entry of kind ``"mcp_tool_call"``.

The actual HTTP transport is delegated to FastMCP from the official
``mcp`` SDK. We layer policy on top: each registered tool runs through
:meth:`MCPGate.invoke`, which enforces rate-limit, runs the tool,
catches :class:`ToolError`, and emits an audit entry.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
from time import perf_counter
from typing import Any

from secops_term.core import audit as audit_mod
from secops_term.mcp.gate import (
    DEFAULT_PER_TOOL_RATE,
    RateLimited,
    RateLimiter,
    Unauthorized,
    check_bearer_token,
)
from secops_term.mcp.tools import MCP_TOOLS, ToolError, ToolSpec


class MCPServerError(Exception):
    """MCP server configuration / startup error."""


def _validate_loopback(host: str) -> str:
    """Reject any host that isn't a loopback address.

    Brief §3.5.9 hard-rejects non-loopback binds. Accepts IPv4
    ``127.0.0.0/8`` and IPv6 ``::1`` only. Hostnames like
    ``localhost`` are NOT accepted — DNS could be lying.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise MCPServerError(
            f"host must be a literal IP loopback address (got {host!r}); "
            "hostnames like 'localhost' are rejected per brief §3.5.9"
        ) from exc
    if not addr.is_loopback:
        raise MCPServerError(
            f"refusing to bind {host} — only loopback (127.x.x.x / ::1) is allowed"
        )
    return host


class MCPGate:
    """Per-call policy gate: auth + rate-limit + audit + ToolError handling.

    Wraps each ``ToolSpec.handler`` so the FastMCP layer only sees a
    plain async callable. The bearer-token check runs on **every**
    invocation when ``expected_token`` is set; FastMCP doesn't expose
    request headers consistently across transports, so we accept the
    token via a per-call ``__authorization__`` argument the client
    smuggles in (only when auth is required).
    """

    def __init__(
        self,
        *,
        audit_logger: audit_mod.AuditLogger,
        rate_limiter: RateLimiter | None = None,
        expected_token: str | None = None,
    ) -> None:
        self._audit = audit_logger
        self._limiter = rate_limiter or RateLimiter()
        self._token = expected_token

    @property
    def auth_required(self) -> bool:
        return self._token is not None

    async def invoke(self, spec: ToolSpec, args: dict[str, Any]) -> dict[str, Any]:
        """Run ``spec.handler`` under the policy umbrella."""
        # Pull the auth header out of the call dict — clients put it
        # in ``__authorization__`` so FastMCP transport-agnostic.
        auth_header = args.pop("__authorization__", None)
        try:
            check_bearer_token(self._token, auth_header)
        except Unauthorized as exc:
            self._emit_audit(spec.name, args, ok=False, error=f"unauthorized: {exc}")
            raise
        try:
            self._limiter.acquire(spec.name)
        except RateLimited as exc:
            self._emit_audit(spec.name, args, ok=False, error=f"rate_limited: {exc}")
            raise

        start = perf_counter()
        try:
            result = await spec.handler(args)
        except ToolError as exc:
            elapsed_ms = (perf_counter() - start) * 1000.0
            self._emit_audit(
                spec.name,
                args,
                ok=False,
                error=f"tool_error: {exc}",
                latency_ms=elapsed_ms,
            )
            raise
        except Exception as exc:
            elapsed_ms = (perf_counter() - start) * 1000.0
            self._emit_audit(
                spec.name,
                args,
                ok=False,
                error=f"{type(exc).__name__}: {str(exc)[:200]}",
                latency_ms=elapsed_ms,
            )
            raise
        elapsed_ms = (perf_counter() - start) * 1000.0
        self._emit_audit(spec.name, args, ok=True, latency_ms=elapsed_ms)
        return result

    def _emit_audit(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        ok: bool,
        error: str | None = None,
        latency_ms: float | None = None,
    ) -> None:
        # Audit args must be JSON-serialisable for the canonical hash.
        # Keys with non-JSONable values get stringified. Token-bearing
        # smuggle key (``__authorization__``) is already popped before
        # we reach here; if it slipped through, redact it here.
        safe_args = _safe_args_for_audit(args)
        entry: dict[str, Any] = {
            "kind": "mcp_tool_call",
            "tool": tool,
            "args": safe_args,
            "ok": ok,
        }
        if error is not None:
            entry["error"] = error
        if latency_ms is not None:
            entry["latency_ms"] = round(latency_ms, 3)
        with contextlib.suppress(Exception):
            self._audit.emit(entry)


def _safe_args_for_audit(args: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for k, v in args.items():
        if k == "__authorization__":
            continue
        try:
            json.dumps(v)
            safe[k] = v
        except (TypeError, ValueError):
            safe[k] = repr(v)
    return safe


def build_fastmcp_server(
    *,
    host: str,
    port: int,
    audit_logger: audit_mod.AuditLogger,
    expected_token: str | None = None,
    per_tool_rate: int = DEFAULT_PER_TOOL_RATE,
    tool_overrides: dict[str, ToolSpec] | None = None,
) -> Any:
    """Construct a FastMCP server bound to a loopback address.

    Returns the underlying ``FastMCP`` instance so the caller can
    invoke ``.run("streamable-http")`` (or whatever transport they
    want). Importing FastMCP is deferred to here so testing the gate
    layer doesn't require the ``mcp`` package to be installed.
    """
    _validate_loopback(host)
    if port < 1024 or port > 65535:
        raise MCPServerError(
            f"port must be in 1024..65535 (got {port}); reserved ports "
            "rejected to avoid clashing with privileged services"
        )

    from mcp.server import FastMCP  # type: ignore[import-not-found,unused-ignore]

    gate = MCPGate(
        audit_logger=audit_logger,
        rate_limiter=RateLimiter(default_limit=per_tool_rate),
        expected_token=expected_token,
    )
    tools = tool_overrides if tool_overrides is not None else MCP_TOOLS
    fmcp = FastMCP(
        name="secops-term",
        host=host,
        port=port,
    )

    for spec in tools.values():
        _register_tool(fmcp, gate, spec)
    return fmcp


def _register_tool(fmcp: Any, gate: MCPGate, spec: ToolSpec) -> None:
    """Register one ToolSpec with FastMCP via the ``add_tool`` shim."""

    async def _wrapper(arguments: dict[str, Any]) -> dict[str, Any]:
        # FastMCP passes the validated arguments dict; we layer policy.
        return await gate.invoke(spec, dict(arguments))

    # FastMCP's API for adding tools shifted across versions; we use
    # the lower-level ``add_tool`` so we can attach the JSON-Schema
    # input_schema verbatim.
    fmcp.add_tool(
        _wrapper,
        name=spec.name,
        description=spec.description,
    )


__all__ = [
    "MCPGate",
    "MCPServerError",
    "build_fastmcp_server",
]
