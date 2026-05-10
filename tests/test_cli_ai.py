"""CLI: ``secops-term ai query`` and ``secops-term ai status``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secops_term.ai import bridge as bridge_mod
from secops_term.cli import app

runner = CliRunner()


@pytest.fixture
def stub_transports(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace ``_build_ai_bridge_candidates`` so tests don't shell out.

    Returns a single fake transport that echoes a canned UDM query.
    """
    from secops_term.ai import selector

    class _StubBridge:
        async def complete(
            self,
            prompt: str,
            *,
            system: str | None = None,
            untrusted_inputs: list[str] | None = None,
        ) -> str:
            return 'metadata.event_type = "NETWORK_DNS"'

        async def health_check(self) -> bool:
            return True

    def _candidates() -> list[selector.TransportCandidate]:
        return [selector.TransportCandidate(_StubBridge(), "stub-transport")]

    monkeypatch.setattr("secops_term.cli._build_ai_bridge_candidates", _candidates)


@pytest.fixture
def stub_no_transports(monkeypatch: pytest.MonkeyPatch) -> None:
    from secops_term.ai import selector

    def _empty() -> list[selector.TransportCandidate]:
        return []

    monkeypatch.setattr("secops_term.cli._build_ai_bridge_candidates", _empty)


# ai query


def test_ai_query_runs_and_displays_result(tmp_root: Path, stub_transports: None) -> None:
    result = runner.invoke(app, ["ai", "query", "--target", "udm", "all DNS events"])
    assert result.exit_code == 0, result.stdout
    assert 'metadata.event_type = "NETWORK_DNS"' in result.stdout
    assert "stub-transport" in result.stdout
    assert "never auto-executes" in result.stdout.lower()


def test_ai_query_default_target_is_udm(tmp_root: Path, stub_transports: None) -> None:
    result = runner.invoke(app, ["ai", "query", "find DNS"])
    assert result.exit_code == 0
    assert 'metadata.event_type = "NETWORK_DNS"' in result.stdout


def test_ai_query_invalid_target_rejected(tmp_root: Path, stub_transports: None) -> None:
    result = runner.invoke(app, ["ai", "query", "--target", "splunk", "find logs"])
    assert result.exit_code != 0
    assert "udm" in result.stdout.lower() or "tmv1" in result.stdout.lower()


def test_ai_query_no_transport_available_exits_nonzero(
    tmp_root: Path, stub_no_transports: None
) -> None:
    result = runner.invoke(app, ["ai", "query", "find DNS"])
    assert result.exit_code != 0
    assert "transport" in result.stdout.lower()


def test_ai_query_writes_audit_entry(tmp_root: Path, stub_transports: None) -> None:
    result = runner.invoke(app, ["ai", "query", "--target", "udm", "find logs"])
    assert result.exit_code == 0
    audit_path = tmp_root / "audit.jsonl"
    assert audit_path.exists()
    entries = [json.loads(line) for line in audit_path.read_text().splitlines() if line]
    ai_entries = [e for e in entries if e["entry"].get("kind") == "ai_call"]
    assert len(ai_entries) == 1
    assert ai_entries[0]["entry"]["transport"] == "stub-transport"
    # No prompt/response leaked without --debug-ai.
    assert "prompt" not in ai_entries[0]["entry"]
    assert "response" not in ai_entries[0]["entry"]


def test_ai_query_debug_ai_includes_full_text(tmp_root: Path, stub_transports: None) -> None:
    result = runner.invoke(app, ["ai", "query", "--debug-ai", "--target", "udm", "find logs"])
    assert result.exit_code == 0
    audit_path = tmp_root / "audit.jsonl"
    entries = [json.loads(line) for line in audit_path.read_text().splitlines() if line]
    ai_entry = next(e for e in entries if e["entry"].get("kind") == "ai_call")
    assert "prompt" in ai_entry["entry"]
    assert "response" in ai_entry["entry"]


# ai status


def test_ai_status_reports_per_transport(tmp_root: Path, stub_transports: None) -> None:
    result = runner.invoke(app, ["ai", "status"])
    assert result.exit_code == 0
    assert "stub-transport" in result.stdout
    assert "yes" in result.stdout.lower()


def test_ai_status_reports_when_claude_missing(
    tmp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default candidate list with no claude binary still runs (clipboard
    falls back to whatever pyperclip says)."""
    monkeypatch.setattr(bridge_mod.shutil, "which", lambda _x: None)
    result = runner.invoke(app, ["ai", "status"])
    assert result.exit_code == 0
    # Either clipboard is healthy ("yes") or it isn't ("no") — the
    # important thing is that a missing claude doesn't crash the table.
    assert "clipboard" in result.stdout
    assert "claude-headless" not in result.stdout
