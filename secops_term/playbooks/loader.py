"""Playbook YAML → :class:`Playbook` loader.

Per brief v3 §6.4: playbooks live in ``~/.secops-term/playbooks/`` as
YAML files. Loading is strict — Pydantic v2 validates the document
before the engine sees it. Untrusted data inside ``{{ ... }}`` is
forbidden by the sandbox, but the YAML structure itself is operator-
authored and treated as trusted.

Path safety: we restrict reads to files under the playbooks root so a
crafted relative path (``../../etc/passwd``) can't sneak through. The
loader uses :func:`secops_term.core.paths.safe_join`.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from secops_term.core import paths
from secops_term.playbooks.schema import Playbook


class PlaybookError(Exception):
    """Generic playbook load / validate failure."""


class PlaybookNotFound(PlaybookError):
    """No playbook with that name."""


_DEFAULT_DIR_NAME = "playbooks"
_YAML = YAML(typ="safe")
# safe loader rejects unknown tags and arbitrary Python objects.


def playbooks_root() -> Path:
    """Return the directory holding playbook YAML files."""
    return paths.get_root() / _DEFAULT_DIR_NAME


def load_playbook_text(text: str) -> Playbook:
    """Parse a YAML string into a :class:`Playbook`.

    Raises :class:`PlaybookError` on parse / validation failure.
    """
    try:
        data: Any = _YAML.load(StringIO(text))
    except YAMLError as exc:
        raise PlaybookError(f"YAML parse error: {exc}") from exc
    if data is None:
        raise PlaybookError("playbook YAML is empty")
    if not isinstance(data, dict):
        raise PlaybookError(f"top-level YAML must be a mapping, got {type(data).__name__}")
    try:
        return Playbook.model_validate(data)
    except ValidationError as exc:
        raise PlaybookError(f"schema validation failed:\n{exc}") from exc


def load_playbook_file(path: Path) -> Playbook:
    """Read and parse a single YAML file.

    Raises :class:`PlaybookNotFound` if the file is missing.
    """
    if not path.exists():
        raise PlaybookNotFound(f"no playbook at {path}")
    text = path.read_text(encoding="utf-8")
    return load_playbook_text(text)


def load_playbook_by_name(name: str) -> Playbook:
    """Load a playbook by its file-stem name from the playbooks root.

    Looks for ``<root>/<name>.yaml`` first, then ``<name>.yml``. Path is
    confined to the root via :func:`paths.safe_join`.
    """
    root = playbooks_root()
    if not root.exists():
        raise PlaybookNotFound(
            f"no playbooks directory at {root} (run `secops-term playbooks init` to create one)"
        )
    for ext in (".yaml", ".yml"):
        candidate = paths.safe_join(root, name + ext)
        if candidate.exists():
            return load_playbook_file(candidate)
    raise PlaybookNotFound(f"no playbook named {name!r} in {root} (tried .yaml and .yml)")


def list_playbooks() -> list[Path]:
    """Return absolute paths of every YAML in the playbooks root.

    Sorted by filename for deterministic CLI output. Files outside the
    root (symlink targets, etc.) are silently ignored — defence in depth
    on top of paths.safe_join.
    """
    root = playbooks_root()
    if not root.exists():
        return []
    candidates: list[Path] = []
    for ext in ("*.yaml", "*.yml"):
        candidates.extend(root.glob(ext))
    return sorted(p for p in candidates if p.is_file() and p.parent == root)


__all__ = [
    "PlaybookError",
    "PlaybookNotFound",
    "list_playbooks",
    "load_playbook_by_name",
    "load_playbook_file",
    "load_playbook_text",
    "playbooks_root",
]
