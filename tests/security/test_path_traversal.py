"""``safe_join`` must reject every shape of traversal."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from secops_term.core import paths

pytestmark = pytest.mark.security


def test_safe_join_basic(tmp_path: Path) -> None:
    out = paths.safe_join(tmp_path, "sub", "file.txt")
    assert out == (tmp_path / "sub" / "file.txt").resolve()


def test_safe_join_rejects_dotdot(tmp_path: Path) -> None:
    with pytest.raises(paths.TraversalError):
        paths.safe_join(tmp_path, "..", "outside.txt")


def test_safe_join_rejects_absolute_posix() -> None:
    if os.name == "nt":
        pytest.skip("POSIX absolute path test")
    with pytest.raises(paths.TraversalError):
        paths.safe_join(Path("/tmp"), "/etc/passwd")  # noqa: S108 — test fixture


def test_safe_join_rejects_absolute_windows() -> None:
    if os.name != "nt":
        pytest.skip("Windows absolute path test")
    with pytest.raises(paths.TraversalError):
        paths.safe_join(Path("C:\\Temp"), "C:\\Windows\\System32\\config\\SAM")


def test_safe_join_rejects_dotdot_buried(tmp_path: Path) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()
    with pytest.raises(paths.TraversalError):
        paths.safe_join(tmp_path, "sub", "..", "..", "outside")


def test_safe_join_allows_dot(tmp_path: Path) -> None:
    out = paths.safe_join(tmp_path, ".", "file.txt")
    assert out == (tmp_path / "file.txt").resolve()


def test_safe_join_allows_root_itself(tmp_path: Path) -> None:
    out = paths.safe_join(tmp_path)
    assert out == tmp_path.resolve()


def test_safe_join_handles_symlinks_outside(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink creation requires Admin or developer mode on Windows")
    target = tmp_path.parent / f"outside-{tmp_path.name}"
    target.mkdir(exist_ok=True)
    try:
        link = tmp_path / "evil"
        link.symlink_to(target)
        with pytest.raises(paths.TraversalError):
            paths.safe_join(tmp_path, "evil", "victim.txt")
    finally:
        if target.exists():
            for child in target.iterdir():
                child.unlink()
            target.rmdir()


def test_safe_join_pathlike_objects(tmp_path: Path) -> None:
    out = paths.safe_join(tmp_path, Path("sub"), Path("file.txt"))
    assert out == (tmp_path / "sub" / "file.txt").resolve()


def test_acl_verification_rejects_world_readable_posix(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode test")
    f = tmp_path / "leaky"
    f.write_text("oops")
    f.chmod(0o644)
    with pytest.raises(paths.RestrictiveACLError):
        paths.verify_restrictive_acl(f)


def test_acl_apply_then_verify_posix(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode test")
    f = tmp_path / "fine"
    f.write_text("ok")
    paths.apply_restrictive_acl(f)
    paths.verify_restrictive_acl(f)
