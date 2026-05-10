"""Bridge selector — picks first healthy transport, wraps in AuditingBridge."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secops_term.ai import selector
from secops_term.ai.audit import AuditingBridge
from secops_term.core import audit as audit_mod


class _StubBridge:
    def __init__(self, *, healthy: bool, response: str = "ok") -> None:
        self._healthy = healthy
        self._response = response
        self.completes_called = 0

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        untrusted_inputs: list[str] | None = None,
    ) -> str:
        self.completes_called += 1
        return self._response

    async def health_check(self) -> bool:
        return self._healthy


class _BlowingBridge:
    """Health check raises — selector should treat as unhealthy."""

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        untrusted_inputs: list[str] | None = None,
    ) -> str:
        return ""

    async def health_check(self) -> bool:
        raise RuntimeError("transport blew up probing itself")


def _read_entries(path: Path) -> list[dict[str, object]]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


# compose_bridge


async def test_picks_first_healthy_candidate(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    primary = _StubBridge(healthy=True, response="from-primary")
    secondary = _StubBridge(healthy=True, response="from-secondary")
    bridge = await selector.compose_bridge(
        [
            selector.TransportCandidate(primary, "headless"),
            selector.TransportCandidate(secondary, "clipboard"),
        ],
        audit_logger=log,
    )
    assert isinstance(bridge, AuditingBridge)
    assert bridge.transport == "headless"
    assert await bridge.complete("p") == "from-primary"
    assert primary.completes_called == 1
    assert secondary.completes_called == 0


async def test_falls_through_to_next_when_primary_unhealthy(
    tmp_root: Path,
) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    primary = _StubBridge(healthy=False, response="never")
    secondary = _StubBridge(healthy=True, response="from-secondary")
    bridge = await selector.compose_bridge(
        [
            selector.TransportCandidate(primary, "headless"),
            selector.TransportCandidate(secondary, "clipboard"),
        ],
        audit_logger=log,
    )
    assert bridge.transport == "clipboard"
    assert await bridge.complete("p") == "from-secondary"


async def test_health_check_exception_treated_as_unhealthy(
    tmp_root: Path,
) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    primary = _BlowingBridge()
    secondary = _StubBridge(healthy=True, response="from-secondary")
    bridge = await selector.compose_bridge(
        [
            selector.TransportCandidate(primary, "headless"),
            selector.TransportCandidate(secondary, "clipboard"),
        ],
        audit_logger=log,
    )
    assert bridge.transport == "clipboard"


async def test_no_healthy_transport_raises(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    a = _StubBridge(healthy=False)
    c = _StubBridge(healthy=False)
    with pytest.raises(selector.NoTransportAvailable):
        await selector.compose_bridge(
            [
                selector.TransportCandidate(a, "headless"),
                selector.TransportCandidate(c, "clipboard"),
            ],
            audit_logger=log,
        )


async def test_empty_candidate_list_raises(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    with pytest.raises(selector.NoTransportAvailable):
        await selector.compose_bridge([], audit_logger=log)


async def test_selected_transport_audited_on_use(tmp_root: Path) -> None:
    """End-to-end: selector chooses, AuditingBridge wraps, complete() emits."""
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    bridge = await selector.compose_bridge(
        [
            selector.TransportCandidate(
                _StubBridge(healthy=True, response="hi"),
                "test-transport",
            )
        ],
        audit_logger=log,
    )
    await bridge.complete("ping")
    entries = _read_entries(log.path)
    assert len(entries) == 1
    entry = entries[0]["entry"]
    assert entry["kind"] == "ai_call"
    assert entry["transport"] == "test-transport"
    assert entry["ok"] is True


async def test_debug_ai_propagates_to_wrapper(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    bridge = await selector.compose_bridge(
        [
            selector.TransportCandidate(
                _StubBridge(healthy=True, response="hi"),
                "t",
            )
        ],
        audit_logger=log,
        debug_ai=True,
    )
    await bridge.complete("ping")
    entry = _read_entries(log.path)[0]["entry"]
    assert entry["prompt"] == "ping"
    assert entry["response"] == "hi"
