"""Threat-intel provider registry.

Concrete providers (``abuse_ch``, ``otx``, ``rss``, ``virustotal``,
``greynoise``, ``abuseipdb``, ``nvd``) register themselves via the
``@PROVIDERS.register("name")`` decorator at module import time. Phase 0
ships no concrete providers; the mechanics (Protocol + registry +
discovery) are here so Phase 1+ can drop modules in without restructuring.
"""

from secops_term.core.registry import Registry, discover_modules
from secops_term.intel.providers.base import (
    IntelProvider,
    IntelProviderError,
    IntelRecord,
)

PROVIDERS: Registry[IntelProvider] = Registry("intel-providers")


def discover() -> list[str]:
    """Import every concrete provider module under this package.

    Returns the names of modules imported. Each module's
    ``@PROVIDERS.register(...)`` decorator runs as a side effect of import.
    """
    return discover_modules(__name__)


__all__ = [
    "PROVIDERS",
    "IntelProvider",
    "IntelProviderError",
    "IntelRecord",
    "discover",
]
