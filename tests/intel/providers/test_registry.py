"""Intel-provider registry: PROVIDERS exists, discover() works, no concretes shipped."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from secops_term.core.health import HealthStatus
from secops_term.intel import providers
from secops_term.intel.providers import base


def test_providers_registry_exists() -> None:
    assert providers.PROVIDERS.name == "intel-providers"


def test_phase_1_ships_concrete_providers() -> None:
    """Phase 1 ships ``abuse_ch``, ``otx``, ``rss``.

    The autouse session fixture in ``conftest.py`` already discovered them;
    this test confirms both the discover walk and the registry contents.
    """
    found = providers.discover()
    assert set(found) >= {"abuse_ch", "otx", "rss"}
    assert {"abuse_ch", "otx", "rss"}.issubset(set(providers.PROVIDERS.keys()))


def test_register_and_lookup_test_provider() -> None:
    """End-to-end: register a Protocol-conforming class and look it up."""

    @providers.PROVIDERS.register("test-provider")
    class TestProvider:
        name = "test-provider"

        def __init__(self, instance: str, cfg: Mapping[str, Any]) -> None:
            self.instance = instance
            self._cfg = cfg

        @classmethod
        def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> base.IntelProvider:
            return cls(instance, cfg)

        async def pull(self, *, since: datetime | None = None) -> list[base.IntelRecord]:
            return []

        async def health_check(self) -> HealthStatus:
            return HealthStatus(
                ok=True,
                latency_ms=1.0,
                detail="test",
                last_checked=datetime.now(UTC),
            )

    cls = providers.PROVIDERS.get("test-provider")
    assert cls is TestProvider

    instance = cls.from_config("default", {})
    assert isinstance(instance, base.IntelProvider)
    assert instance.instance == "default"
    assert instance.name == "test-provider"


def test_intel_record_dataclass() -> None:
    rec = base.IntelRecord(
        source="otx:default",
        type="sha256",
        value="abc123",
        fetched_at=datetime.now(UTC),
        confidence=85,
    )
    assert rec.source == "otx:default"
    assert rec.tags == ()
    assert rec.context is None


def test_intel_record_with_tags() -> None:
    rec = base.IntelRecord(
        source="abuse_ch:urlhaus",
        type="url",
        value="http://example.com/malware",
        fetched_at=datetime.now(UTC),
        tags=("malware", "phishing"),
    )
    assert rec.tags == ("malware", "phishing")


def test_re_exports_match_base() -> None:
    """Re-exports from the package match the module-level definitions."""
    assert providers.IntelProvider is base.IntelProvider
    assert providers.IntelProviderError is base.IntelProviderError
    assert providers.IntelRecord is base.IntelRecord
