"""Threat-intel provider Protocol and value types.

Concrete provider implementations (``abuse_ch``, ``otx``, ``rss``,
``virustotal``, ``greynoise``, ``abuseipdb``, ``nvd``) implement this
Protocol and register via the decorator exported from
:mod:`secops_term.intel.providers`.

Phase 0 ships no concrete providers. The registry mechanics and Protocol
definitions land here so Phase 1+ can drop concrete modules in without
restructuring.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Protocol, runtime_checkable

from secops_term.core.health import HealthStatus


@dataclass(frozen=True)
class IntelRecord:
    """One row produced by a provider's ``pull()`` method.

    ``source`` follows the convention ``"{provider}:{instance}"`` so the IOC
    store can attribute provenance to a specific provider+instance pair.
    """

    source: str
    type: str  # ipv4, ipv6, domain, url, sha256, sha1, md5, email, cve
    value: str
    fetched_at: datetime
    confidence: int | None = None
    context: str | None = None
    source_ref: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)


class IntelProviderError(Exception):
    """Base class for intel-provider errors."""


@runtime_checkable
class IntelProvider(Protocol):
    """Protocol every threat-intel provider must satisfy.

    Concrete classes register via ``@PROVIDERS.register("name")``. The
    classmethod constructor receives a per-instance config dict drawn from
    ``config.toml``; secrets (API tokens) are fetched separately via the
    secrets manager.
    """

    name: ClassVar[str]
    instance: str

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> IntelProvider:
        """Construct an instance from a config dict.

        ``cfg`` typically contains the provider's portion of ``config.toml``:
        URLs, region pickers, sub-feed toggles. Secrets live elsewhere.
        """
        ...

    async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
        """Fetch new IOCs since ``since`` (or all available if ``None``)."""
        ...

    async def health_check(self) -> HealthStatus:
        """Cheapest auth-validating probe for this provider+instance."""
        ...
