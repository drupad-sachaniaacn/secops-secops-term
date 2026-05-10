"""Intel orchestrator: walks config, runs providers, upserts results."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from secops_term.core import config_io
from secops_term.core import db as core_db
from secops_term.core.health import HealthStatus
from secops_term.intel import orchestrator
from secops_term.intel import store as store_mod
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers.base import IntelProviderError, IntelRecord

# Synthetic providers registered per-test (autouse snapshot/restore cleans up).


def _register_static(records: list[IntelRecord], *, fail: bool = False) -> str:
    """Register a synthetic provider that returns a fixed record list."""

    @PROVIDERS.register("synthetic-static")
    class _Static:
        name = "synthetic-static"

        def __init__(self, instance: str, cfg: Mapping[str, Any]) -> None:
            self.instance = instance
            self._cfg = cfg

        @classmethod
        def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> _Static:
            return cls(instance, cfg)

        async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
            if fail:
                raise RuntimeError("simulated failure")
            return list(records)

        async def health_check(self) -> HealthStatus:
            return HealthStatus(
                ok=True,
                latency_ms=1.0,
                detail="ok",
                last_checked=datetime.now(UTC),
            )

    return "synthetic-static"


# Walk + filter


async def test_pull_all_with_no_config(migrated_db: core_db.Database, tmp_root: object) -> None:
    results = await orchestrator.pull_all(cfg_data={}, store=store_mod.IOCStore(migrated_db))
    assert results == []


async def test_pull_all_skips_disabled_instances(
    migrated_db: core_db.Database, tmp_root: object
) -> None:
    name = _register_static([])
    cfg = {
        "intel_providers": {
            name: {
                "primary": {"enabled": False},
                "secondary": {"enabled": True},
            }
        }
    }
    results = await orchestrator.pull_all(cfg_data=cfg, store=store_mod.IOCStore(migrated_db))
    assert [r.instance for r in results] == ["secondary"]


async def test_pull_all_provider_filter(migrated_db: core_db.Database, tmp_root: object) -> None:
    name = _register_static([])
    cfg = {
        "intel_providers": {
            name: {
                "default": {"enabled": True},
                "other": {"enabled": True},
            }
        }
    }
    results = await orchestrator.pull_all(
        cfg_data=cfg,
        store=store_mod.IOCStore(migrated_db),
        provider_filter=name,
        instance_filter="other",
    )
    assert [r.instance for r in results] == ["other"]


# Pull → upsert flow


async def test_pull_all_upserts_new_records(
    migrated_db: core_db.Database, tmp_root: object
) -> None:
    records = [
        IntelRecord(
            source="synthetic-static:default",
            type="ipv4",
            value="8.8.8.8",
            fetched_at=datetime.now(UTC),
        ),
        IntelRecord(
            source="synthetic-static:default",
            type="sha256",
            value="a" * 64,
            fetched_at=datetime.now(UTC),
        ),
    ]
    name = _register_static(records)
    cfg = {"intel_providers": {name: {"default": {"enabled": True}}}}
    store = store_mod.IOCStore(migrated_db)
    results = await orchestrator.pull_all(cfg_data=cfg, store=store)
    assert len(results) == 1
    r = results[0]
    assert r.ok is True
    assert r.total == 2
    assert r.new == 2
    assert r.reobserved == 0
    assert store.count() == 2


async def test_pull_all_classifies_reobservations(
    migrated_db: core_db.Database, tmp_root: object
) -> None:
    records = [
        IntelRecord(
            source="synthetic-static:default",
            type="ipv4",
            value="8.8.8.8",
            fetched_at=datetime.now(UTC),
        ),
    ]
    name = _register_static(records)
    cfg = {"intel_providers": {name: {"default": {"enabled": True}}}}
    store = store_mod.IOCStore(migrated_db)
    first = await orchestrator.pull_all(cfg_data=cfg, store=store)
    second = await orchestrator.pull_all(cfg_data=cfg, store=store)
    assert first[0].new == 1
    assert second[0].new == 0
    assert second[0].reobserved == 1


async def test_pull_all_captures_provider_failure(
    migrated_db: core_db.Database, tmp_root: object
) -> None:
    name = _register_static([], fail=True)
    cfg = {"intel_providers": {name: {"default": {"enabled": True}}}}
    results = await orchestrator.pull_all(cfg_data=cfg, store=store_mod.IOCStore(migrated_db))
    assert len(results) == 1
    assert results[0].ok is False
    assert "simulated failure" in (results[0].error or "")


async def test_pull_all_unregistered_provider(
    migrated_db: core_db.Database, tmp_root: object
) -> None:
    cfg = {"intel_providers": {"no-such-provider": {"default": {"enabled": True}}}}
    results = await orchestrator.pull_all(cfg_data=cfg, store=store_mod.IOCStore(migrated_db))
    assert len(results) == 1
    assert results[0].ok is False
    assert "not registered" in (results[0].error or "")


async def test_pull_all_from_config_failure(
    migrated_db: core_db.Database, tmp_root: object
) -> None:
    @PROVIDERS.register("synthetic-bad-config")
    class _BadConfig:
        name = "synthetic-bad-config"
        instance = ""

        @classmethod
        def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> _BadConfig:
            raise IntelProviderError("missing field")

        async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
            return []

        async def health_check(self) -> HealthStatus:
            return HealthStatus(ok=True, latency_ms=0, detail="-", last_checked=datetime.now(UTC))

    cfg = {"intel_providers": {"synthetic-bad-config": {"default": {"enabled": True}}}}
    results = await orchestrator.pull_all(cfg_data=cfg, store=store_mod.IOCStore(migrated_db))
    assert results[0].ok is False
    assert "missing field" in (results[0].error or "")


# Health targets


def test_build_health_targets_skips_unregistered() -> None:
    cfg = {
        "intel_providers": {
            "no-such": {"default": {"enabled": True}},
        }
    }
    assert orchestrator.build_health_targets(cfg_data=cfg) == []


def test_build_health_targets_yields_one_per_enabled_instance() -> None:
    name = _register_static([])
    cfg = {
        "intel_providers": {
            name: {
                "primary": {"enabled": True},
                "secondary": {"enabled": True},
                "third": {"enabled": False},
            }
        }
    }
    out = orchestrator.build_health_targets(cfg_data=cfg)
    instances = [label for _, label in out]
    assert sorted(instances) == ["primary", "secondary"]


# Config-driven path (load_config integration)


async def test_pull_all_reads_config_from_disk(
    migrated_db: core_db.Database, tmp_root: object
) -> None:
    name = _register_static(
        [
            IntelRecord(
                source=f"{name_via_register():synthetic}:default",
                type="ipv4",
                value="9.9.9.9",
                fetched_at=datetime.now(UTC),
            )
        ]
        if False
        else []  # placeholder branch — not used
    )
    config_io.save_config({"intel_providers": {name: {"default": {"enabled": True}}}})
    results = await orchestrator.pull_all(store=store_mod.IOCStore(migrated_db))
    assert results
    assert results[0].provider == name


def name_via_register() -> str:  # pragma: no cover
    """Helper: Python doesn't allow forward reference inside decorators inline."""
    return "x"


# Sync wrapper


async def test_pull_all_sync_runs(migrated_db: core_db.Database, tmp_root: object) -> None:
    """``pull_all_sync`` is just an ``asyncio.run`` wrapper.

    Skipped here because pytest-asyncio's auto mode would call it inside an
    already-running loop. Direct ``asyncio.run`` from a sync test would
    fight the event loop. See test_cli_intel for the CLI-level invocation.
    """
    pytest.skip("covered via test_cli_intel.py end-to-end")
