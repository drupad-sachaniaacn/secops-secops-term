#!/usr/bin/env python
"""Cross-platform PyInstaller build helper for SecOps Terminal.

Usage
-----
From the repo root (with PyInstaller installed in the active venv):

    python scripts/build_dist.py

Or, to pass extra PyInstaller flags:

    python scripts/build_dist.py --clean --noconfirm

The resulting directory bundle lands at ``dist/secops-term/``.  Rename /
zip it before distributing:

    Windows : dist\\secops-term\\secops-term.exe
    macOS   : dist/secops-term/secops-term
    Linux   : dist/secops-term/secops-term

Requirements
------------
- PyInstaller >= 6.7  (``pip install "secops-term[build]"``)
- UPX (optional, reduces binary size ~30 %):
    Windows : https://upx.github.io/
    macOS   : ``brew install upx``
    Linux   : ``apt install upx-ucl`` / ``dnf install upx``

Platform-specific notes
-----------------------
Windows
    If ``codesign`` is desired, sign ``dist\\secops-term\\secops-term.exe``
    after build using ``signtool``.

macOS
    After build, deep-sign with::

        codesign --deep --force --sign - dist/secops-term/secops-term

    then optionally create a ``.dmg`` with ``create-dmg`` or ``hdiutil``.

Linux
    The bundle is a directory; distribute as a tarball or AppImage.
    Example AppImage workflow::

        wget https://github.com/AppImage/AppImageKit/releases/latest/…/appimagetool
        appimagetool dist/secops-term secops-term-0.6.0-x86_64.AppImage
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SPEC = _REPO_ROOT / "secops_term.spec"


def main(extra_args: list[str]) -> None:
    pyinstaller_exe = _check_pyinstaller()
    print(f"[build] Building SecOps Terminal from {_SPEC}")
    cmd = [sys.executable, "-m", "PyInstaller", str(_SPEC), *extra_args]
    result = subprocess.run(cmd, cwd=_REPO_ROOT, check=False)  # noqa: S603
    if result.returncode != 0:
        print("[build] PyInstaller exited with non-zero status.", file=sys.stderr)
        sys.exit(result.returncode)
    dist_dir = _REPO_ROOT / "dist" / "secops-term"
    if not dist_dir.exists():
        print(f"[build] Expected output at {dist_dir} — not found.", file=sys.stderr)
        sys.exit(1)
    exe_name = "secops-term.exe" if sys.platform == "win32" else "secops-term"
    exe = dist_dir / exe_name
    print(f"\n[build] Success! Executable: {exe}")
    print(f"[build] Bundle directory: {dist_dir}")
    del pyinstaller_exe  # used for version display; suppress unused-variable lint
    _print_platform_notes(dist_dir, exe)


def _check_pyinstaller() -> str:
    """Return the PyInstaller executable path, or exit if not found."""
    # Prefer the module invocation so we use the right venv's copy.
    probe = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--version"],
        capture_output=True,
        check=False,
    )
    if probe.returncode == 0:
        ver = probe.stdout.decode().strip()
        print(f"[build] Using PyInstaller {ver} (via python -m PyInstaller)")
        return sys.executable

    # Fall back to the ``pyinstaller`` script on PATH.
    exe = shutil.which("pyinstaller")
    if exe is None:
        print(
            '[build] PyInstaller not found. Install with:\n    pip install "secops-term[build]"',
            file=sys.stderr,
        )
        sys.exit(1)
    probe2 = subprocess.run(  # noqa: S603
        [exe, "--version"], capture_output=True, check=False
    )
    ver = probe2.stdout.decode().strip()
    print(f"[build] Using PyInstaller {ver} ({exe})")
    return exe


def _print_platform_notes(dist_dir: Path, exe: Path) -> None:
    platform = sys.platform
    print()
    if platform == "win32":
        print("[build] Windows: sign the binary with signtool before distribution.")
        print(f"[build] Distribute the entire directory: {dist_dir}")
        print(f"[build] Entry point: {exe}")
    elif platform == "darwin":
        print("[build] macOS: deep-sign with:")
        print(f"    codesign --deep --force --sign - {exe}")
        print("[build] Then optionally wrap in a .dmg with hdiutil or create-dmg.")
    else:
        print("[build] Linux: distribute as a tarball or AppImage.")
        print(
            f"    tar czf secops-term-0.6.0-linux-x86_64.tar.gz -C {dist_dir.parent} secops-term/"
        )
        print("[build] Or use appimagetool to create an AppImage.")


if __name__ == "__main__":
    main(sys.argv[1:])
