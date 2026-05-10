"""``discover_modules`` walks a package and imports every concrete submodule."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from secops_term.core import registry


def _cleanup_fake_pkg(name: str) -> None:
    for mod_name in list(sys.modules.keys()):
        if mod_name == name or mod_name.startswith(f"{name}."):
            del sys.modules[mod_name]


def test_discover_imports_all_concrete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Create a fake package with multiple modules; discover() imports them all."""
    pkg_dir = tmp_path / "fake_pkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")
    (pkg_dir / "base.py").write_text("# base — should be skipped\n")
    (pkg_dir / "concrete_a.py").write_text("VALUE = 'A'\n")
    (pkg_dir / "concrete_b.py").write_text("VALUE = 'B'\n")
    (pkg_dir / "_internal.py").write_text("# leading underscore — skipped\n")

    monkeypatch.syspath_prepend(str(tmp_path))
    try:
        names = registry.discover_modules("fake_pkg")
        assert sorted(names) == ["concrete_a", "concrete_b"]
        assert "fake_pkg.concrete_a" in sys.modules
        assert "fake_pkg.concrete_b" in sys.modules
        assert "fake_pkg._internal" not in sys.modules
    finally:
        _cleanup_fake_pkg("fake_pkg")


def test_discover_skip_extra(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pkg_dir = tmp_path / "fake_pkg2"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")
    (pkg_dir / "concrete_a.py").write_text("VALUE = 'A'\n")
    (pkg_dir / "concrete_b.py").write_text("VALUE = 'B'\n")

    monkeypatch.syspath_prepend(str(tmp_path))
    try:
        names = registry.discover_modules("fake_pkg2", skip=("concrete_b",))
        assert names == ["concrete_a"]
    finally:
        _cleanup_fake_pkg("fake_pkg2")


def test_discover_empty_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pkg_dir = tmp_path / "empty_pkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")

    monkeypatch.syspath_prepend(str(tmp_path))
    try:
        names = registry.discover_modules("empty_pkg")
        assert names == []
    finally:
        _cleanup_fake_pkg("empty_pkg")


def test_discover_runs_register_decorators(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: a module that registers on import populates the registry."""
    pkg_dir = tmp_path / "fake_pkg3"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text(
        "from secops_term.core.registry import Registry\nREGISTRY = Registry('fake')\n"
    )
    (pkg_dir / "alpha.py").write_text(
        "from fake_pkg3 import REGISTRY\n@REGISTRY.register('alpha')\nclass Alpha:\n    pass\n"
    )

    monkeypatch.syspath_prepend(str(tmp_path))
    try:
        registry.discover_modules("fake_pkg3")
        import fake_pkg3  # type: ignore[import-not-found]

        assert "alpha" in fake_pkg3.REGISTRY
    finally:
        _cleanup_fake_pkg("fake_pkg3")
