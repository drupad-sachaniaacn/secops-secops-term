"""MCP server: loopback enforcement + MCPGate integration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secops_term.core import audit as audit_mod
from secops_term.mcp import server as server_mod
from secops_term.mcp import tools as tools_mod
from secops_term.mcp.gate import RateLimited, RateLimiter, Unauthorized

# _validate_loopback


@pytest.mark.parametrize("host", ["127.0.0.1", "127.5.6.7", "::1"])
def test_loopback_addresses_accepted(host: str) -> None:
    assert server_mod._validate_loopback(host) == host


@pytest.mark.parametrize(
    "host",
    [
        "0.0.0.0",  # noqa: S104 - test asserts this gets REJECTED
        "8.8.8.8",
        "10.0.0.1",
        "169.254.169.254",  # AWS metadata
        "192.168.1.1",
        "::",
        "2001:db8::1",
    ],
)
def test_non_loopback_rejected(host: str) -> None:
    with pytest.raises(server_mod.MCPServerError):
        server_mod._validate_loopback(host)


def test_hostname_rejected() -> None:
    """``localhost`` is NOT accepted — DNS could be lying."""
    with pytest.raises(server_mod.MCPServerError):
        server_mod._validate_loopback("localhost")


def test_garbage_host_rejected() -> None:
    with pytest.raises(server_mod.MCPServerError):
        server_mod._validate_loopback("not-an-ip")


# build_fastmcp_server (validates without actually starting the server)


def test_build_fastmcp_rejects_non_loopback(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    with pytest.raises(server_mod.MCPServerError):
        server_mod.build_fastmcp_server(
            host="0.0.0.0",  # noqa: S104 - test asserts this gets REJECTED
            port=8765,
            audit_logger=log,
        )


def test_build_fastmcp_rejects_privileged_port(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    with pytest.raises(server_mod.MCPServerError):
        server_mod.build_fastmcp_server(host="127.0.0.1", port=80, audit_logger=log)


def test_build_fastmcp_loopback_succeeds(tmp_root: Path) -> None:
    """Smoke: a loopback bind succeeds and returns a FastMCP instance."""
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    fmcp = server_mod.build_fastmcp_server(host="127.0.0.1", port=18765, audit_logger=log)
    # Don't run it — just verify the object came back.
    assert fmcp is not None


# MCPGate (no FastMCP needed)


async def test_gate_invokes_tool_on_success(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    gate = server_mod.MCPGate(audit_logger=log)
    spec = tools_mod.ToolSpec(
        name="echo",
        description="echo",
        input_schema={"type": "object"},
        handler=lambda args: _async({"echo": args}),
    )
    out = await gate.invoke(spec, {"x": 1})
    assert out == {"echo": {"x": 1}}


async def test_gate_audits_success(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    gate = server_mod.MCPGate(audit_logger=log)
    spec = tools_mod.ToolSpec(
        name="t",
        description="",
        input_schema={"type": "object"},
        handler=lambda args: _async({"ok": True}),
    )
    await gate.invoke(spec, {"a": 1})
    entries = _read_entries(log.path)
    assert len(entries) == 1
    e = entries[0]["entry"]
    assert e["kind"] == "mcp_tool_call"
    assert e["tool"] == "t"
    assert e["ok"] is True
    assert e["args"] == {"a": 1}
    assert "latency_ms" in e


async def test_gate_audits_tool_error(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    gate = server_mod.MCPGate(audit_logger=log)

    async def _fail(_args: dict) -> dict:
        raise tools_mod.ToolError("bad input")

    spec = tools_mod.ToolSpec(
        name="t", description="", input_schema={"type": "object"}, handler=_fail
    )
    with pytest.raises(tools_mod.ToolError):
        await gate.invoke(spec, {})
    e = _read_entries(log.path)[0]["entry"]
    assert e["ok"] is False
    assert "tool_error: bad input" in e["error"]


async def test_gate_rejects_unauthorized(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    gate = server_mod.MCPGate(audit_logger=log, expected_token="secret")
    spec = tools_mod.ToolSpec(
        name="t",
        description="",
        input_schema={"type": "object"},
        handler=lambda args: _async({}),
    )
    with pytest.raises(Unauthorized):
        await gate.invoke(spec, {})  # no __authorization__
    e = _read_entries(log.path)[0]["entry"]
    assert e["ok"] is False
    assert "unauthorized" in e["error"]


async def test_gate_passes_with_correct_bearer(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    gate = server_mod.MCPGate(audit_logger=log, expected_token="secret")
    spec = tools_mod.ToolSpec(
        name="t",
        description="",
        input_schema={"type": "object"},
        handler=lambda args: _async({"ok": True}),
    )
    out = await gate.invoke(spec, {"x": 1, "__authorization__": "Bearer secret"})
    assert out == {"ok": True}
    # The auth-header smuggle key must NOT appear in the audit entry.
    e = _read_entries(log.path)[0]["entry"]
    assert "__authorization__" not in e["args"]


async def test_gate_strips_auth_header_from_args(tmp_root: Path) -> None:
    """Even on failure path, the bearer token must not leak to audit."""
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    gate = server_mod.MCPGate(audit_logger=log, expected_token="secret")
    spec = tools_mod.ToolSpec(
        name="t",
        description="",
        input_schema={"type": "object"},
        handler=lambda args: _async({}),
    )
    with pytest.raises(Unauthorized):
        await gate.invoke(spec, {"__authorization__": "Bearer wrong", "y": 2})
    e = _read_entries(log.path)[0]["entry"]
    assert "__authorization__" not in e["args"]
    assert e["args"] == {"y": 2}


async def test_gate_enforces_rate_limit(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    rl = RateLimiter(default_limit=2)
    gate = server_mod.MCPGate(audit_logger=log, rate_limiter=rl)
    spec = tools_mod.ToolSpec(
        name="t",
        description="",
        input_schema={"type": "object"},
        handler=lambda args: _async({"ok": True}),
    )
    await gate.invoke(spec, {})
    await gate.invoke(spec, {})
    with pytest.raises(RateLimited):
        await gate.invoke(spec, {})
    # Last entry is the rate-limit denial.
    last = _read_entries(log.path)[-1]["entry"]
    assert last["ok"] is False
    assert "rate_limited" in last["error"]


# Helpers


async def _async(v):  # type: ignore[no-untyped-def]
    return v


def _read_entries(path: Path) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line:
                out.append(json.loads(line))
    return out
