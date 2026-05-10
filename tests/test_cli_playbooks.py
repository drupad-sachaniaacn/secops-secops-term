"""CLI: ``secops-term playbooks list / show / init / run``."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from secops_term.cli import app

runner = CliRunner()


_GOOD_YAML = """\
name: cli-test-pb
trigger:
  type: manual
steps:
  - id: notify_step
    type: notify
    channel: slack:soc-alerts
    summary: hello
    message: world
"""


def _seed_playbook(tmp_root: Path, name: str, content: str = _GOOD_YAML) -> Path:
    root = tmp_root / "playbooks"
    root.mkdir(parents=True, exist_ok=True)
    p = root / f"{name}.yaml"
    p.write_text(content, encoding="utf-8")
    return p


# list


def test_list_no_dir(tmp_root: Path) -> None:
    result = runner.invoke(app, ["playbooks", "list"])
    assert result.exit_code == 0
    assert "No playbooks" in result.stdout


def test_list_shows_each(tmp_root: Path) -> None:
    _seed_playbook(tmp_root, "alpha")
    _seed_playbook(tmp_root, "beta")
    result = runner.invoke(app, ["playbooks", "list"])
    assert result.exit_code == 0
    assert "alpha" in result.stdout
    assert "beta" in result.stdout


def test_list_flags_invalid(tmp_root: Path) -> None:
    _seed_playbook(tmp_root, "bad", "name: no_steps\n")
    result = runner.invoke(app, ["playbooks", "list"])
    assert result.exit_code == 0
    assert "ERROR" in result.stdout


# show


def test_show_prints_details(tmp_root: Path) -> None:
    _seed_playbook(tmp_root, "alpha")
    result = runner.invoke(app, ["playbooks", "show", "alpha"])
    assert result.exit_code == 0
    assert "cli-test-pb" in result.stdout
    assert "notify_step" in result.stdout


def test_show_missing(tmp_root: Path) -> None:
    result = runner.invoke(app, ["playbooks", "show", "ghost"])
    assert result.exit_code != 0


# init


def test_init_writes_three_examples(tmp_root: Path) -> None:
    result = runner.invoke(app, ["playbooks", "init"])
    assert result.exit_code == 0
    root = tmp_root / "playbooks"
    files = sorted(p.name for p in root.glob("*.yaml"))
    assert files == [
        "daily-feed-pull.yaml",
        "high-conf-ioc-followup.yaml",
        "weekly-osint-roundup.yaml",
    ]


def test_init_skips_existing_unless_force(tmp_root: Path) -> None:
    runner.invoke(app, ["playbooks", "init"])
    # Modify one file to test that re-running doesn't overwrite.
    target = tmp_root / "playbooks" / "high-conf-ioc-followup.yaml"
    target.write_text("name: hand-edited\ntrigger:\n  type: manual\nsteps: []\n")
    result = runner.invoke(app, ["playbooks", "init"])
    assert result.exit_code == 0
    assert "Skipped" in result.stdout
    assert "hand-edited" in target.read_text()


def test_init_force_overwrites(tmp_root: Path) -> None:
    runner.invoke(app, ["playbooks", "init"])
    target = tmp_root / "playbooks" / "high-conf-ioc-followup.yaml"
    target.write_text("name: hand-edited\ntrigger:\n  type: manual\nsteps: []\n")
    result = runner.invoke(app, ["playbooks", "init", "--force"])
    assert result.exit_code == 0
    # Force overwrote — original example name is back.
    assert "hand-edited" not in target.read_text()


# run --dry-run


def test_run_dry_run_succeeds(tmp_root: Path) -> None:
    _seed_playbook(tmp_root, "alpha")
    result = runner.invoke(app, ["playbooks", "run", "alpha", "--dry-run"])
    assert result.exit_code == 0, result.stdout
    assert "OK" in result.stdout
    assert "notify_step" in result.stdout


def test_run_ioc_added_without_id_rejected(tmp_root: Path) -> None:
    _seed_playbook(
        tmp_root,
        "tracker",
        "name: tracker\ntrigger:\n  type: ioc_added\n"
        "steps:\n  - id: n\n    type: notify\n    channel: slack:x\n"
        "    summary: 's'\n    message: 'm'\n",
    )
    result = runner.invoke(app, ["playbooks", "run", "tracker"])
    assert result.exit_code != 0
    assert "ioc_added" in result.stdout


def test_run_emits_audit_entries(tmp_root: Path) -> None:
    _seed_playbook(tmp_root, "alpha")
    runner.invoke(app, ["playbooks", "run", "alpha", "--dry-run"])
    audit_path = tmp_root / "audit.jsonl"
    assert audit_path.exists()
    entries = [json.loads(line) for line in audit_path.read_text().splitlines() if line]
    pb_entries = [e for e in entries if e["entry"].get("kind") == "playbook_step"]
    assert len(pb_entries) == 1
    assert pb_entries[0]["entry"]["dry_run"] is True
    assert pb_entries[0]["entry"]["ok"] is True
