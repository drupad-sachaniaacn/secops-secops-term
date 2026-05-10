"""Basic happy-path tests for path helpers (security edge-cases live in tests/security/)."""

from __future__ import annotations

import os
from pathlib import Path

from secops_term.core import paths


def test_get_root_default() -> None:
    paths.set_root_for_tests(None)
    root = paths.get_root()
    assert root.name == ".secops-term"
    assert root.is_absolute()


def test_get_root_override(tmp_path: Path) -> None:
    paths.set_root_for_tests(tmp_path)
    try:
        assert paths.get_root() == tmp_path.resolve()
    finally:
        paths.set_root_for_tests(None)


def test_ensure_root_initialized_creates_dir(tmp_path: Path) -> None:
    target = tmp_path / "nested" / ".secops-term"
    paths.set_root_for_tests(target)
    try:
        paths.ensure_root_initialized()
        assert target.is_dir()
        if os.name != "nt":
            mode = target.stat().st_mode & 0o777
            assert mode == 0o700
    finally:
        paths.set_root_for_tests(None)


def test_ensure_root_initialized_idempotent(tmp_root: Path) -> None:
    paths.ensure_root_initialized()
    paths.ensure_root_initialized()
    assert tmp_root.is_dir()
