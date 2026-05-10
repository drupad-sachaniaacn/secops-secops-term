"""CLI: command invocation via Typer's CliRunner."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from secops_term import __version__
from secops_term.cli import app
from secops_term.core import audit, config_io, paths

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("version", "tui", "doctor", "config", "audit"):
        assert cmd in result.stdout


def test_doctor_runs_on_fresh_install(tmp_root: Path) -> None:
    result = runner.invoke(app, ["doctor"])
    # Fresh install — no root yet, but check is OK (not a failure).
    assert result.exit_code == 0
    assert "Doctor" in result.stdout
    assert "root directory" in result.stdout
    assert "claude on PATH" in result.stdout


def test_audit_verify_no_log(tmp_root: Path) -> None:
    result = runner.invoke(app, ["audit", "verify"])
    assert result.exit_code == 0
    assert "No audit log" in result.stdout or "nothing to verify" in result.stdout


def test_audit_verify_clean_chain(tmp_root: Path) -> None:
    log = audit.AuditLogger(path=tmp_root / "audit.jsonl")
    log.emit({"event": "first"})
    log.emit({"event": "second"})
    result = runner.invoke(app, ["audit", "verify"])
    assert result.exit_code == 0
    assert "OK" in result.stdout
    assert "2 entries" in result.stdout


def test_audit_verify_detects_tamper(tmp_root: Path) -> None:
    p = tmp_root / "audit.jsonl"
    log = audit.AuditLogger(path=p)
    log.emit({"event": "first"})
    log.emit({"event": "second"})
    # Tamper one line.
    lines = p.read_text(encoding="utf-8").splitlines()
    import json

    parsed = json.loads(lines[1])
    parsed["entry"] = {"event": "TAMPERED"}
    lines[1] = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = runner.invoke(app, ["audit", "verify"])
    assert result.exit_code == 1
    assert "CHAIN BROKEN" in result.stdout


def test_config_show_no_config(tmp_root: Path) -> None:
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "No config.toml" in result.stdout


def test_config_show_with_data(tmp_root: Path) -> None:
    paths.ensure_root_initialized()
    config_io.save_config({"chronicle": {"customer_id": "abc-123", "region": "us"}})
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "chronicle" in result.stdout
    assert "abc-123" in result.stdout


def test_config_test_requires_provider_argument() -> None:
    result = runner.invoke(app, ["config", "test"])
    # Typer surfaces missing required argument with exit code 2.
    assert result.exit_code != 0


def test_config_test_all_no_config(tmp_root: Path) -> None:
    result = runner.invoke(app, ["config", "test-all"])
    assert result.exit_code == 0
    assert "No configured intel providers" in result.stdout
