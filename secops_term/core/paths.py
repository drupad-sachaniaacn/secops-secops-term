"""Path safety: root-pinned writes, ACL enforcement, traversal rejection.

All persistent files written by SecOps Terminal live under ``~/.secops-term/``.
This module pins that root at startup and provides ``safe_join`` to compose
paths under it without traversal.

ACL rules (per brief v3 §3.5.6):
- POSIX: file mode ``0o600``, directory mode ``0o700``. Set on every write,
  verified on every read.
- Windows: explicit ACL via ``icacls`` removing all groups, granting only
  the current user (and SYSTEM for OS administration). Verified on read
  via ``pywin32``'s ``GetFileSecurity``.

If verification fails, callers raise :class:`RestrictiveACLError` and the app
refuses to operate on that path. There is no auto-repair: the brief
requires an explicit error so the user notices misconfiguration.
"""

from __future__ import annotations

import getpass
import os
import platform
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

WINDOWS = platform.system() == "Windows"
USER_DATA_DIRNAME = ".secops-term"


class PathSafetyError(Exception):
    """Base class for path-safety violations."""


class TraversalError(PathSafetyError):
    """Resolved path escapes the pinned root."""


class RestrictiveACLError(PathSafetyError):
    """File ACLs are not restrictive enough to hold secrets/audit data."""


_root_override: Path | None = None


def set_root_for_tests(path: Path | None) -> None:
    """Override the user-data root. Tests only — production code never calls this."""
    global _root_override
    _root_override = path


def get_root() -> Path:
    """Resolve the user-data root: ``~/.secops-term/`` (or the test override)."""
    if _root_override is not None:
        return _root_override.resolve()
    return (Path.home() / USER_DATA_DIRNAME).resolve()


def ensure_root_initialized() -> Path:
    """Create the user-data root if missing, with restrictive permissions."""
    root = get_root()
    root.mkdir(parents=True, exist_ok=True)
    apply_restrictive_acl(root, is_dir=True)
    return root


def safe_join(root: Path, *parts: str | os.PathLike[str]) -> Path:
    """Join ``parts`` under ``root``, rejecting traversal.

    - Each part must be a relative path (no absolute paths in user input).
    - The fully-resolved result must be a descendant of ``root`` (or ``root``
      itself).

    Raises :class:`TraversalError` on violation.
    """
    root_resolved = root.resolve(strict=False)
    candidate = root_resolved
    for part in parts:
        p = Path(os.fspath(part))
        if p.is_absolute():
            raise TraversalError(f"absolute path component rejected: {part!r}")
        candidate = candidate / p

    final = candidate.resolve(strict=False)
    if final != root_resolved:
        try:
            final.relative_to(root_resolved)
        except ValueError as exc:
            raise TraversalError(
                f"resolved path escapes root: {final} not under {root_resolved}"
            ) from exc
    return final


def apply_restrictive_acl(path: Path, *, is_dir: bool = False) -> None:
    """Apply restrictive permissions to ``path``.

    POSIX: ``chmod 0o600`` (file) or ``0o700`` (dir).
    Windows: ``icacls /inheritance:r /grant:r <user>:F SYSTEM:F``.
    """
    if WINDOWS:
        _apply_windows_acl(path)
    else:
        path.chmod(0o700 if is_dir else 0o600)


def verify_restrictive_acl(path: Path, *, is_dir: bool = False) -> None:
    """Verify that ``path`` has a restrictive ACL. Raise if not."""
    if WINDOWS:
        _verify_windows_acl(path)
    else:
        _verify_posix_mode(path, is_dir=is_dir)


def _verify_posix_mode(path: Path, *, is_dir: bool) -> None:
    info = path.stat()
    mode = stat.S_IMODE(info.st_mode)
    expected = 0o700 if is_dir else 0o600
    if mode & 0o077:
        raise RestrictiveACLError(
            f"{path} has permissive mode 0o{mode:03o}; expected 0o{expected:03o}"
        )


def _current_user_account() -> str:
    user = getpass.getuser()
    if not user:
        raise RestrictiveACLError("cannot determine current user for ACL operations")
    return user


def _apply_windows_acl(path: Path) -> None:
    """Replace the DACL with: current user (full) + SYSTEM (full), nothing else.

    Python's ``mkdir`` on Windows seeds new directories with explicit
    (non-inherited) ACEs for ``Administrators`` and ``OWNER RIGHTS`` derived
    from the parent's inheritable ACEs, so ``/inheritance:r`` alone does
    not remove them. We follow the inheritance reset with explicit
    ``/remove:g`` calls for those principals to land on a clean DACL.
    """
    icacls = shutil.which("icacls")
    if icacls is None:
        raise RestrictiveACLError("icacls not on PATH; cannot set Windows ACL")
    user = _current_user_account()
    # `(OI)(CI)F` = full control + Object Inherit + Container Inherit, so
    # files created inside this directory inherit the same ACEs (which is
    # what we need so sqlite, audit log writes, etc. work for the owner).
    grant = "(OI)(CI)F" if path.is_dir() else "F"
    cmd = [
        icacls,
        str(path),
        "/inheritance:r",
        "/grant:r",
        f"{user}:{grant}",
        f"SYSTEM:{grant}",
        # Strip the inheritable-default principals that mkdir copied in.
        # /remove:g is idempotent — absent principals don't fail the call.
        "/remove:g",
        "Administrators",
        "/remove:g",
        "*S-1-3-4",  # OWNER RIGHTS well-known SID
    ]
    result = subprocess.run(  # noqa: S603 — argv list, no shell, fixed icacls path
        cmd, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        detail = (result.stderr.strip() or result.stdout.strip()) or "no detail"
        raise RestrictiveACLError(f"icacls failed for {path}: {detail}")


def _verify_windows_acl(path: Path) -> None:
    """Verify that the only DACL principals are the current user and SYSTEM."""
    win32security: Any
    try:
        import win32security as win32security_mod  # type: ignore[import-not-found,import-untyped,unused-ignore]
    except ImportError as exc:  # pragma: no cover
        raise RestrictiveACLError("pywin32 not installed; cannot verify Windows ACLs") from exc
    win32security = win32security_mod

    sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        raise RestrictiveACLError(f"{path} has no DACL set")

    user_sid, _, _ = win32security.LookupAccountName(None, _current_user_account())
    system_sid, _, _ = win32security.LookupAccountName(None, "SYSTEM")
    allowed_sids = {bytes(user_sid), bytes(system_sid)}

    for i in range(dacl.GetAceCount()):
        ace = dacl.GetAce(i)
        ace_sid = ace[2]
        if bytes(ace_sid) not in allowed_sids:
            raise RestrictiveACLError(f"{path} DACL contains unexpected principal in ACE #{i}")
