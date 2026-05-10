"""``doctor``: every check, against various filesystem states."""

from __future__ import annotations

import os
from pathlib import Path

from secops_term.core import audit, config_io, doctor, paths


def test_doctor_fresh_install(tmp_path: Path, monkeypatch) -> None:
    """Fresh install — no root, no config — should pass overall."""
    fresh = tmp_path / "no-root-yet"
    paths.set_root_for_tests(fresh)
    try:
        results = doctor.run_doctor()
        assert doctor.overall_ok(results) is True
        names = {r.name for r in results}
        assert names >= {
            "root directory",
            "config.toml",
            "secrets.enc",
            "audit chain",
            "keyring",
            "claude on PATH",
        }
    finally:
        paths.set_root_for_tests(None)


def test_doctor_with_root_initialized(tmp_root: Path) -> None:
    paths.ensure_root_initialized()
    results = doctor.run_doctor()
    assert doctor.overall_ok(results) is True
    root_check = next(r for r in results if r.name == "root directory")
    assert root_check.ok is True
    assert str(tmp_root.resolve()) in root_check.detail


def test_doctor_detects_permissive_root(tmp_root: Path) -> None:
    if os.name == "nt":
        # Setting permissive ACL on Windows requires more setup; skip.
        return
    paths.ensure_root_initialized()
    tmp_root.chmod(0o755)  # group/world readable — permissive
    results = doctor.run_doctor()
    root_check = next(r for r in results if r.name == "root directory")
    assert root_check.ok is False
    assert "permissive" in root_check.detail


def test_doctor_with_audit_chain(tmp_root: Path) -> None:
    log = audit.AuditLogger(path=tmp_root / "audit.jsonl")
    log.emit({"event": "test"})
    log.emit({"event": "test"})
    results = doctor.run_doctor()
    audit_check = next(r for r in results if r.name == "audit chain")
    assert audit_check.ok is True
    assert "verified 2 entries" in audit_check.detail


def test_doctor_with_config_present(tmp_root: Path) -> None:
    paths.ensure_root_initialized()
    config_io.save_config({"chronicle": {"customer_id": "x"}})
    results = doctor.run_doctor()
    cfg_check = next(r for r in results if r.name == "config.toml")
    assert cfg_check.ok is True
    assert "1 top-level table" in cfg_check.detail


def test_doctor_detects_corrupt_config(tmp_root: Path) -> None:
    paths.ensure_root_initialized()
    bad = config_io.config_path()
    bad.write_text("not = valid\nfoo bar", encoding="utf-8")
    paths.apply_restrictive_acl(bad)
    results = doctor.run_doctor()
    cfg_check = next(r for r in results if r.name == "config.toml")
    assert cfg_check.ok is False


def test_format_table_shape(tmp_root: Path) -> None:
    results = doctor.run_doctor()
    rows = doctor.format_table(results)
    assert all(len(row) == 3 for row in rows)
    assert all(row[1] in ("OK", "FAIL") for row in rows)
