"""Notifier registry.

Concrete notifiers (``generic_json``, ``slack``, ``teams``) register via
``@NOTIFIERS.register("name")`` at module import time. Three built-ins
ship in Phase 5: ``generic_json``, ``slack``, ``teams``. Adding a new
notifier is a one-file drop here plus a tests/notifications/ module.
"""

from secops_term.core.registry import Registry, discover_modules
from secops_term.notifications.base import (
    Notifier,
    NotifierError,
    NotifyPayload,
    NotifyResult,
    Severity,
)

NOTIFIERS: Registry[Notifier] = Registry("notifiers")


def discover() -> list[str]:
    """Import every concrete notifier module under this package."""
    return discover_modules(__name__)


__all__ = [
    "NOTIFIERS",
    "Notifier",
    "NotifierError",
    "NotifyPayload",
    "NotifyResult",
    "Severity",
    "discover",
]
