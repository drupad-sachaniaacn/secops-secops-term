"""CLI: ``intel pull`` and ``config test`` / ``test-all`` against real providers."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from secops_term.cli import app
from secops_term.core import config_io
from secops_term.core import db as core_db
from secops_term.core.health import HealthStatus
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers.base import IntelRecord

runner = CliRunner()


def _register_static_provider(
    *,
    name: str = "cli-static",
    records: list[IntelRecord] | None = None,
    health_ok: bool = True,
) -> None:
    """Register a synthetic provider with predictable pull + health output."""
    rec_list = list(records or [])

    @PROVIDERS.register(name)
    class _Static:
        registered_name = name

        def __init__(self, instance: str, cfg: Mapping[str, Any]) -> None:
            self.name = name
            self.instance = instance
            self._cfg = cfg

        @classmethod
        def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> _Static:
            return cls(instance, cfg)

        async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
            return list(rec_list)

        async def health_check(self) -> HealthStatus:
            return HealthStatus(
                ok=health_ok,
                latency_ms=4.2,
                detail="all good" if health_ok else "synthetic failure",
                last_checked=datetime.now(UTC),
            )


@pytest.fixture
def configured_static_provider(tmp_root: Path, migrated_db: core_db.Database) -> None:
    """Wire a synthetic provider into config.toml + register it."""
    records = [
        IntelRecord(
            source="cli-static:default",
            type="ipv4",
            value="8.8.8.8",
            fetched_at=datetime.now(UTC),
        ),
        IntelRecord(
            source="cli-static:default",
            type="sha256",
            value="a" * 64,
            fetched_at=datetime.now(UTC),
        ),
    ]
    _register_static_provider(records=records)
    config_io.save_config({"intel_providers": {"cli-static": {"default": {"enabled": True}}}})


# intel pull


def test_intel_pull_writes_records_into_store(
    configured_static_provider: None,
) -> None:
    result = runner.invoke(app, ["intel", "pull"])
    assert result.exit_code == 0, result.stdout
    assert "cli-static" in result.stdout
    assert "Total" in result.stdout or "total" in result.stdout.lower()
    # Verify the store has the upserted records.
    from secops_term.intel import store as store_mod

    s = store_mod.get_default_store()
    try:
        assert s.count() == 2
        assert s.get("ipv4", "8.8.8.8") is not None
    finally:
        s.database.close()


def test_intel_pull_with_no_config_emits_message(tmp_root: Path) -> None:
    result = runner.invoke(app, ["intel", "pull"])
    assert result.exit_code == 0
    assert "No matching configured providers" in result.stdout


def test_intel_pull_provider_filter(
    configured_static_provider: None,
) -> None:
    result = runner.invoke(app, ["intel", "pull", "--provider", "cli-static"])
    assert result.exit_code == 0
    assert "cli-static" in result.stdout


def test_intel_pull_provider_filter_misses(
    configured_static_provider: None,
) -> None:
    result = runner.invoke(app, ["intel", "pull", "--provider", "no-such"])
    assert result.exit_code == 0
    assert "No matching configured providers" in result.stdout


def test_intel_pull_invalid_since(
    configured_static_provider: None,
) -> None:
    result = runner.invoke(app, ["intel", "pull", "--since", "not-a-date"])
    assert result.exit_code == 1
    assert "Invalid --since" in result.stdout


def test_intel_pull_failed_provider_returns_nonzero(
    tmp_root: Path, migrated_db: core_db.Database
) -> None:
    """A pull failure should produce exit code 1 and surface the error."""

    @PROVIDERS.register("cli-failing")
    class _Failing:
        name = "cli-failing"

        def __init__(self, instance: str, cfg: Mapping[str, Any]) -> None:
            self.instance = instance

        @classmethod
        def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> _Failing:
            return cls(instance, cfg)

        async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
            raise RuntimeError("boom")

        async def health_check(self) -> HealthStatus:
            return HealthStatus(
                ok=False,
                latency_ms=0.0,
                detail="-",
                last_checked=datetime.now(UTC),
            )

    config_io.save_config({"intel_providers": {"cli-failing": {"default": {"enabled": True}}}})
    result = runner.invoke(app, ["intel", "pull"])
    assert result.exit_code == 1
    assert "error" in result.stdout.lower()
    assert "boom" in result.stdout


# intel list


def test_intel_list_empty(tmp_root: Path, migrated_db: core_db.Database) -> None:
    result = runner.invoke(app, ["intel", "list"])
    assert result.exit_code == 0
    assert "(no IOCs)" in result.stdout


def test_intel_list_after_pull(
    configured_static_provider: None,
) -> None:
    runner.invoke(app, ["intel", "pull"])
    result = runner.invoke(app, ["intel", "list"])
    assert result.exit_code == 0
    assert "8.8.8.8" in result.stdout
    assert "ipv4" in result.stdout


def test_intel_list_filters_by_type(
    configured_static_provider: None,
) -> None:
    runner.invoke(app, ["intel", "pull"])
    result = runner.invoke(app, ["intel", "list", "--type", "ipv4"])
    assert result.exit_code == 0
    assert "8.8.8.8" in result.stdout
    assert "a" * 64 not in result.stdout


def test_intel_list_search(configured_static_provider: None) -> None:
    runner.invoke(app, ["intel", "pull"])
    result = runner.invoke(app, ["intel", "list", "--search", "8.8.8"])
    assert result.exit_code == 0
    assert "8.8.8.8" in result.stdout
    assert "a" * 64 not in result.stdout


# config test


def test_config_test_unconfigured(tmp_root: Path) -> None:
    result = runner.invoke(app, ["config", "test", "abuse_ch"])
    assert result.exit_code == 1
    assert "No config" in result.stdout


def test_config_test_unregistered(tmp_root: Path) -> None:
    config_io.save_config({"intel_providers": {"no-such": {"default": {"enabled": True}}}})
    result = runner.invoke(app, ["config", "test", "no-such"])
    assert result.exit_code == 1
    assert "not registered" in result.stdout


def test_config_test_succeeds(tmp_root: Path) -> None:
    _register_static_provider(name="cli-healthy", health_ok=True)
    config_io.save_config({"intel_providers": {"cli-healthy": {"default": {"enabled": True}}}})
    result = runner.invoke(app, ["config", "test", "cli-healthy"])
    assert result.exit_code == 0
    assert "OK" in result.stdout
    assert "all good" in result.stdout


def test_config_test_fails(tmp_root: Path) -> None:
    _register_static_provider(name="cli-broken", health_ok=False)
    config_io.save_config({"intel_providers": {"cli-broken": {"default": {"enabled": True}}}})
    result = runner.invoke(app, ["config", "test", "cli-broken"])
    assert result.exit_code == 1
    assert "FAIL" in result.stdout
    assert "synthetic failure" in result.stdout


# config test-all


def test_config_test_all_no_config(tmp_root: Path) -> None:
    result = runner.invoke(app, ["config", "test-all"])
    assert result.exit_code == 0
    assert "No configured intel providers" in result.stdout


def test_config_test_all_runs_every_target(tmp_root: Path) -> None:
    _register_static_provider(name="cli-h1", health_ok=True)
    _register_static_provider(name="cli-h2", health_ok=True)
    config_io.save_config(
        {
            "intel_providers": {
                "cli-h1": {"default": {"enabled": True}},
                "cli-h2": {
                    "primary": {"enabled": True},
                    "secondary": {"enabled": True},
                },
            }
        }
    )
    result = runner.invoke(app, ["config", "test-all"])
    assert result.exit_code == 0
    # 3 health rows (one per enabled instance).
    assert "cli-h1" in result.stdout
    assert "cli-h2" in result.stdout
    assert "primary" in result.stdout
    assert "secondary" in result.stdout


# intel export


def test_intel_export_stix_empty_store(tmp_root: Path, migrated_db: core_db.Database) -> None:
    result = runner.invoke(app, ["intel", "export", "--format", "stix"])
    assert result.exit_code == 0
    import json

    parsed = json.loads(result.stdout)
    assert parsed["type"] == "bundle"
    assert parsed["objects"] == []


def test_intel_export_stix_after_pull(configured_static_provider: None) -> None:
    """Pull some IOCs, then export as STIX — bundle should contain all of them."""
    runner.invoke(app, ["intel", "pull"])
    result = runner.invoke(app, ["intel", "export", "--format", "stix"])
    assert result.exit_code == 0, result.stdout
    import json

    parsed = json.loads(result.stdout)
    assert parsed["type"] == "bundle"
    # 2 IOCs pulled: ipv4 + sha256
    assert len(parsed["objects"]) == 2
    types = {obj["type"] for obj in parsed["objects"]}
    assert "ipv4-addr" in types
    assert "file" in types


def test_intel_export_stix_type_filter(configured_static_provider: None) -> None:
    runner.invoke(app, ["intel", "pull"])
    result = runner.invoke(app, ["intel", "export", "--format", "stix", "--type", "ipv4"])
    assert result.exit_code == 0
    import json

    parsed = json.loads(result.stdout)
    assert all(obj["type"] == "ipv4-addr" for obj in parsed["objects"])


def test_intel_export_stix_to_file(
    tmp_root: Path, migrated_db: core_db.Database, tmp_path: Path
) -> None:
    out_file = tmp_path / "export.json"
    result = runner.invoke(app, ["intel", "export", "--format", "stix", "--out", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()
    import json

    parsed = json.loads(out_file.read_text())
    assert parsed["type"] == "bundle"


def test_intel_export_unknown_format(tmp_root: Path) -> None:
    result = runner.invoke(app, ["intel", "export", "--format", "csv"])
    assert result.exit_code == 1
    assert "Unknown format" in result.stdout
