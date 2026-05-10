"""AuditingBridge — wraps any AIBridge and emits audit entries."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from secops_term.ai import audit as ai_audit
from secops_term.ai.bridge import AIBridge
from secops_term.core import audit as audit_mod


class _FakeBridge:
    """Minimal AIBridge for the wrapper to delegate to."""

    def __init__(
        self,
        *,
        response: str = "ok",
        raise_exc: Exception | None = None,
        sleep_s: float = 0.0,
    ) -> None:
        self.response = response
        self.raise_exc = raise_exc
        self.sleep_s = sleep_s
        self.calls: list[dict[str, object]] = []

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        untrusted_inputs: list[str] | None = None,
    ) -> str:
        self.calls.append({"prompt": prompt, "system": system, "untrusted": untrusted_inputs})
        if self.sleep_s:
            await asyncio.sleep(self.sleep_s)
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.response

    async def health_check(self) -> bool:
        return True


def _read_entries(path: Path) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            out.append(json.loads(line))
    return out


def _ensure_protocol_satisfied(b: AIBridge) -> AIBridge:
    """Static check that AuditingBridge satisfies the AIBridge Protocol."""
    return b


# Success path


async def test_audit_emits_entry_on_success(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    inner = _FakeBridge(response="hello")
    wrapped = ai_audit.AuditingBridge(inner, audit_logger=log, transport="claude-headless")
    _ensure_protocol_satisfied(wrapped)

    out = await wrapped.complete("ping", untrusted_inputs=["data1", "data2"])

    assert out == "hello"
    entries = _read_entries(log.path)
    assert len(entries) == 1
    entry = entries[0]["entry"]
    assert entry["kind"] == "ai_call"
    assert entry["transport"] == "claude-headless"
    assert entry["ok"] is True
    assert entry["untrusted_count"] == 2
    assert isinstance(entry["latency_ms"], int | float)
    assert isinstance(entry["prompt_hash"], str)
    assert len(entry["prompt_hash"]) == 16
    assert isinstance(entry["response_hash"], str)
    assert len(entry["response_hash"]) == 16


async def test_audit_omits_full_text_by_default(tmp_root: Path) -> None:
    """No --debug-ai → only hashes leak, never the prompt or response."""
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    inner = _FakeBridge(response="sensitive-response")
    wrapped = ai_audit.AuditingBridge(inner, audit_logger=log, transport="t")
    await wrapped.complete("sensitive-prompt")
    entry = _read_entries(log.path)[0]["entry"]
    assert "prompt" not in entry
    assert "response" not in entry


async def test_audit_includes_full_text_when_debug_ai(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    inner = _FakeBridge(response="full-response")
    wrapped = ai_audit.AuditingBridge(inner, audit_logger=log, transport="t", debug_ai=True)
    await wrapped.complete("full-prompt")
    entry = _read_entries(log.path)[0]["entry"]
    assert entry["prompt"] == "full-prompt"
    assert entry["response"] == "full-response"


async def test_audit_prompt_hash_stable_across_calls(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    inner = _FakeBridge()
    wrapped = ai_audit.AuditingBridge(inner, audit_logger=log, transport="t")
    await wrapped.complete("same prompt", system="sys", untrusted_inputs=["u1"])
    await wrapped.complete("same prompt", system="sys", untrusted_inputs=["u1"])
    entries = _read_entries(log.path)
    assert entries[0]["entry"]["prompt_hash"] == entries[1]["entry"]["prompt_hash"]


async def test_audit_prompt_hash_varies_with_inputs(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    inner = _FakeBridge()
    wrapped = ai_audit.AuditingBridge(inner, audit_logger=log, transport="t")
    await wrapped.complete("a")
    await wrapped.complete("b")
    entries = _read_entries(log.path)
    assert entries[0]["entry"]["prompt_hash"] != entries[1]["entry"]["prompt_hash"]


async def test_audit_response_hash_changes_with_response(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    bridge1 = ai_audit.AuditingBridge(
        _FakeBridge(response="alpha"), audit_logger=log, transport="t"
    )
    bridge2 = ai_audit.AuditingBridge(_FakeBridge(response="beta"), audit_logger=log, transport="t")
    await bridge1.complete("p")
    await bridge2.complete("p")
    entries = _read_entries(log.path)
    assert entries[0]["entry"]["response_hash"] != entries[1]["entry"]["response_hash"]


# Failure path


async def test_audit_emits_failure_entry(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    inner = _FakeBridge(raise_exc=RuntimeError("upstream broke"))
    wrapped = ai_audit.AuditingBridge(inner, audit_logger=log, transport="t")
    with pytest.raises(RuntimeError):
        await wrapped.complete("p")
    entry = _read_entries(log.path)[0]["entry"]
    assert entry["ok"] is False
    assert "RuntimeError" in entry["error"]
    assert "upstream broke" in entry["error"]
    assert "response_hash" not in entry  # no response on failure


async def test_audit_failure_omits_prompt_text_unless_debug(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    wrapped = ai_audit.AuditingBridge(
        _FakeBridge(raise_exc=ValueError("bad")),
        audit_logger=log,
        transport="t",
    )
    with pytest.raises(ValueError):
        await wrapped.complete("secret-prompt")
    entry = _read_entries(log.path)[0]["entry"]
    assert "prompt" not in entry


async def test_audit_failure_includes_prompt_when_debug_ai(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    wrapped = ai_audit.AuditingBridge(
        _FakeBridge(raise_exc=ValueError("bad")),
        audit_logger=log,
        transport="t",
        debug_ai=True,
    )
    with pytest.raises(ValueError):
        await wrapped.complete("secret-prompt")
    entry = _read_entries(log.path)[0]["entry"]
    assert entry["prompt"] == "secret-prompt"


# Latency


async def test_audit_latency_reflects_real_time(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    inner = _FakeBridge(sleep_s=0.05)
    wrapped = ai_audit.AuditingBridge(inner, audit_logger=log, transport="t")
    await wrapped.complete("p")
    entry = _read_entries(log.path)[0]["entry"]
    # 50ms sleep; allow generous margin for slow CI.
    assert entry["latency_ms"] >= 30.0


# Health check passthrough


async def test_audit_health_check_delegates(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    inner = _FakeBridge()
    wrapped = ai_audit.AuditingBridge(inner, audit_logger=log, transport="t")
    assert await wrapped.health_check() is True
    # Health check is bookkeeping, not an AI call — don't audit it.
    assert not log.path.exists() or _read_entries(log.path) == []
