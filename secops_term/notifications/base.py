"""Notifier Protocol and value types.

Concrete notifiers (``generic_json``, ``slack``, ``teams``) implement this
Protocol and register via the decorator exported from
:mod:`secops_term.notifications`.

Phase 0 ships no concrete notifiers. The registry mechanics and Protocol
definitions land here so Phase 5 can drop concrete modules in without
restructuring.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, Literal, Protocol, runtime_checkable

from secops_term.core.health import HealthStatus

Severity = Literal["info", "warn", "error"]


@dataclass(frozen=True)
class NotifyPayload:
    """Input to :meth:`Notifier.send`.

    ``context`` is the playbook context dict at the time of the ``notify``
    step, filtered by the notifier's redaction allowlist.
    """

    summary: str
    body: str
    severity: Severity
    context: Mapping[str, Any]


@dataclass(frozen=True)
class NotifyResult:
    """Outcome of a single :meth:`Notifier.send` call."""

    delivered: bool
    detail: str
    latency_ms: float


class NotifierError(Exception):
    """Base class for notifier errors."""


@runtime_checkable
class Notifier(Protocol):
    """Protocol every notifier must satisfy.

    Concrete classes register via ``@NOTIFIERS.register("name")``. Multi-instance
    is the norm: a single notifier (e.g. ``slack``) typically has many
    configured channels (``slack:soc-alerts``, ``slack:escalations``, ...).
    """

    name: ClassVar[str]
    instance: str

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> Notifier:
        """Construct an instance from a config dict.

        ``cfg`` typically contains the notifier's portion of ``config.toml``:
        URLs (when not credentials), template selection, redaction allowlist.
        Credentials (Slack/Teams webhook URLs, bearer tokens) live in the
        keyring and are fetched separately by the implementation.
        """
        ...

    async def send(self, payload: NotifyPayload) -> NotifyResult:
        """Deliver ``payload``. Returns a result; never raises on transport failure."""
        ...

    async def health_check(self) -> HealthStatus:
        """Cheapest reachability probe for this notifier+instance."""
        ...
