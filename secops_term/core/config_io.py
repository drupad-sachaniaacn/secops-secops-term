"""Read / write ``~/.secops-term/config.toml`` with restrictive ACLs.

Per brief v3 §3.5.2: TOML parsed via stdlib ``tomllib`` (3.11+). Pydantic
schema validation (v3 says) lands in Phases 1-3 alongside the concrete
providers/notifiers — Phase 0 ships an unvalidated read/write so the wizard
and ``doctor`` can operate.

Atomic write: write to a sibling ``.tmp``, apply restrictive ACL, rename.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from secops_term.core import paths

_CONFIG_FILENAME = "config.toml"


class ConfigError(Exception):
    """Base class for config-file errors."""


def config_path() -> Path:
    """Absolute path to ``~/.secops-term/config.toml``."""
    return paths.safe_join(paths.get_root(), _CONFIG_FILENAME)


def load_config() -> dict[str, Any]:
    """Load and parse ``config.toml``. Returns ``{}`` if the file is absent."""
    path = config_path()
    if not path.exists():
        return {}
    paths.verify_restrictive_acl(path)
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"could not parse {path}: {exc}") from exc


def save_config(data: Mapping[str, Any]) -> None:
    """Atomically write ``data`` to ``config.toml`` with mode 0o600 / restricted ACL."""
    path = config_path()
    paths.ensure_root_initialized()
    text = _dump_toml(data)
    tmp = path.with_suffix(path.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)
    paths.apply_restrictive_acl(tmp)
    os.replace(tmp, path)
    paths.apply_restrictive_acl(path)


# Minimal TOML writer for the subset of values the wizard produces.
#
# Supports:
#   - top-level scalars (str, int, float, bool, None → omitted)
#   - nested tables (recursively)
#   - arrays of strings
#
# Does NOT support: arrays of tables, datetimes, multi-line strings, or
# anything else. If a future schema needs them, switch to the ``tomli-w``
# package rather than expanding this writer.


def _dump_toml(data: Mapping[str, Any]) -> str:
    lines: list[str] = []
    _emit_block(lines, [], data)
    out = "\n".join(lines)
    if out and not out.endswith("\n"):
        out += "\n"
    return out


def _emit_block(lines: list[str], key_path: list[str], block: Mapping[str, Any]) -> None:
    scalars = [(k, v) for k, v in block.items() if not isinstance(v, dict)]
    tables = [(k, v) for k, v in block.items() if isinstance(v, dict)]

    if scalars:
        if key_path:
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(f"[{'.'.join(key_path)}]")
        for k, v in scalars:
            if v is None:
                continue
            lines.append(f"{_format_key(k)} = {_format_value(v)}")

    for k, sub in tables:
        _emit_block(lines, [*key_path, k], sub)


def _format_key(key: str) -> str:
    """Quote a TOML key only when needed (contains chars outside [A-Za-z0-9_-])."""
    if all(c.isalnum() or c in "_-" for c in key) and key:
        return key
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _format_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        escaped = v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{escaped}"'
    if isinstance(v, list):
        return "[" + ", ".join(_format_value(x) for x in v) + "]"
    raise TypeError(f"unsupported TOML value of type {type(v).__name__}: {v!r}")


def mask_secret(value: str) -> str:
    """Mask a secret for display: keep last 4 chars, replace the rest with bullets."""
    if len(value) <= 4:
        return "•" * len(value)
    return f"{value[:2]}…{'•' * 4}{value[-4:]}"
