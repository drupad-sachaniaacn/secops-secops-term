"""Pytest configuration and shared fixtures.

Phase 0 scaffold. ``tmp_root`` overrides the user-data root; the autouse
fixtures isolate global registries between tests so a registration in one
test doesn't bleed into the next.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from secops_term.core import paths, redact, secrets
from secops_term.intel.providers import PROVIDERS as INTEL_PROVIDERS
from secops_term.notifications import NOTIFIERS


@pytest.fixture
def tmp_root(tmp_path: Path) -> Iterator[Path]:
    """Override ``paths.get_root()`` to point at a freshly-permed tmp_path."""
    paths.set_root_for_tests(tmp_path)
    paths.apply_restrictive_acl(tmp_path, is_dir=True)
    try:
        yield tmp_path
    finally:
        paths.set_root_for_tests(None)


@pytest.fixture(autouse=True)
def _clean_redact_registry() -> Iterator[None]:
    """Empty the global redaction registry between tests."""
    redact.get_registry().clear()
    try:
        yield
    finally:
        redact.get_registry().clear()


@pytest.fixture(autouse=True)
def _clean_secrets_singleton() -> Iterator[None]:
    """Reset the SecretsManager singleton between tests."""
    secrets.reset_manager_for_tests()
    try:
        yield
    finally:
        secrets.reset_manager_for_tests()


@pytest.fixture(scope="session", autouse=True)
def _discover_concrete_plugins() -> None:
    """Populate the registries with all concrete providers + notifiers once per session.

    Concrete provider/notifier modules register themselves at import time via
    ``@PROVIDERS.register(...)`` / ``@NOTIFIERS.register(...)``. Python caches
    those imports, so the ``@register`` decorators only run once per session.
    Discovering at session start gives every test access to the concretes.
    """
    from secops_term.intel.providers import discover as discover_intel
    from secops_term.notifications import discover as discover_notifiers

    discover_intel()
    discover_notifiers()


@pytest.fixture(autouse=True)
def _isolate_plugin_registries() -> Iterator[None]:
    """Snapshot + restore registries per test so synthetic registrations don't leak.

    Phase 1+ ships concrete providers (and Phase 5 ships concrete notifiers)
    that self-register on first import. ``clear()``-between-tests would wipe
    those — Python's module cache prevents the ``@register`` decorator from
    re-running on subsequent imports. Snapshot/restore preserves whatever was
    registered at session start while removing test-only entries on exit.
    """
    intel_snap = INTEL_PROVIDERS.snapshot()
    notif_snap = NOTIFIERS.snapshot()
    try:
        yield
    finally:
        INTEL_PROVIDERS.restore(intel_snap)
        NOTIFIERS.restore(notif_snap)


@pytest.fixture
def migrated_db(tmp_root: Path) -> Iterator[core_db.Database]:
    """A fresh ``Database`` with all checked-in migrations applied."""
    from secops_term.core import db as core_db

    database = core_db.Database()
    database.apply_migrations(core_db.discover_migrations())
    try:
        yield database
    finally:
        database.close()


from secops_term.core import db as core_db  # noqa: E402 — fixture above uses the module name
