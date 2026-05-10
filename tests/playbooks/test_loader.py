"""Playbook YAML loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from secops_term.playbooks import loader

_GOOD_YAML = """\
name: my-playbook
description: a test
trigger:
  type: manual
steps:
  - id: notify_team
    type: notify
    channel: slack:soc-alerts
    summary: "{{ ioc.value }} hit"
    message: "Details: {{ ioc.value }}"
"""


def test_load_text_returns_playbook() -> None:
    pb = loader.load_playbook_text(_GOOD_YAML)
    assert pb.name == "my-playbook"
    assert pb.steps[0].id == "notify_team"


def test_load_text_empty_rejected() -> None:
    with pytest.raises(loader.PlaybookError, match="empty"):
        loader.load_playbook_text("")


def test_load_text_non_mapping_rejected() -> None:
    with pytest.raises(loader.PlaybookError, match="mapping"):
        loader.load_playbook_text("- a\n- list")


def test_load_text_yaml_parse_error() -> None:
    # Unbalanced brackets — guaranteed YAML parse failure.
    with pytest.raises(loader.PlaybookError, match="parse error"):
        loader.load_playbook_text("name: [unclosed\nfoo: bar")


def test_load_text_schema_violation() -> None:
    with pytest.raises(loader.PlaybookError, match="schema"):
        loader.load_playbook_text("name: x\ntrigger:\n  type: webhook\nsteps: []\n")


def test_load_file_missing(tmp_path: Path) -> None:
    with pytest.raises(loader.PlaybookNotFound):
        loader.load_playbook_file(tmp_path / "nope.yaml")


def test_load_file_round_trip(tmp_path: Path) -> None:
    p = tmp_path / "p.yaml"
    p.write_text(_GOOD_YAML, encoding="utf-8")
    pb = loader.load_playbook_file(p)
    assert pb.name == "my-playbook"


def test_load_by_name_yaml_extension(tmp_root: Path) -> None:
    root = tmp_root / "playbooks"
    root.mkdir(parents=True, exist_ok=True)
    (root / "alpha.yaml").write_text(_GOOD_YAML, encoding="utf-8")
    pb = loader.load_playbook_by_name("alpha")
    assert pb.name == "my-playbook"


def test_load_by_name_yml_extension_too(tmp_root: Path) -> None:
    root = tmp_root / "playbooks"
    root.mkdir(parents=True, exist_ok=True)
    (root / "beta.yml").write_text(_GOOD_YAML, encoding="utf-8")
    pb = loader.load_playbook_by_name("beta")
    assert pb.name == "my-playbook"


def test_load_by_name_missing(tmp_root: Path) -> None:
    (tmp_root / "playbooks").mkdir(parents=True, exist_ok=True)
    with pytest.raises(loader.PlaybookNotFound):
        loader.load_playbook_by_name("ghost")


def test_load_by_name_no_root_dir(tmp_root: Path) -> None:
    with pytest.raises(loader.PlaybookNotFound, match="no playbooks directory"):
        loader.load_playbook_by_name("anything")


def test_load_by_name_path_traversal_rejected(tmp_root: Path) -> None:
    """``safe_join`` blocks ../ escapes; this asserts the loader is wired through it."""
    from secops_term.core.paths import TraversalError

    (tmp_root / "playbooks").mkdir(parents=True, exist_ok=True)
    with pytest.raises(TraversalError):
        loader.load_playbook_by_name("../../etc/passwd")


def test_list_playbooks_returns_sorted(tmp_root: Path) -> None:
    root = tmp_root / "playbooks"
    root.mkdir(parents=True, exist_ok=True)
    for n in ("z.yaml", "a.yaml", "m.yml"):
        (root / n).write_text(_GOOD_YAML, encoding="utf-8")
    paths = loader.list_playbooks()
    names = [p.name for p in paths]
    assert names == ["a.yaml", "m.yml", "z.yaml"]


def test_list_playbooks_no_dir(tmp_root: Path) -> None:
    assert loader.list_playbooks() == []
