"""Chronicle SecOps integration.

- :mod:`secops_term.chronicle.auth` — service-account → OAuth2 token providers.
- :mod:`secops_term.chronicle.client` — UDM Search + health probe.
- :mod:`secops_term.chronicle.retro_hunt` (Phase 2.2) — IOC → UDM query builder
  + retro-hunt-job worker.
"""

from secops_term.chronicle.auth import (
    ChronicleAuth,
    ChronicleAuthError,
    GoogleServiceAccountAuth,
    StaticTokenAuth,
)
from secops_term.chronicle.client import (
    REGION_BASE_URLS,
    ChronicleAPIError,
    ChronicleClient,
    ChronicleConfig,
    ChronicleError,
    UdmSearchResult,
)
from secops_term.chronicle.factory import (
    CHRONICLE_PROVIDER_KEY,
    SA_FIELD,
    build_chronicle_client,
)
from secops_term.chronicle.retro_hunt import (
    CHRONICLE_PLATFORM,
    RetroHuntWorker,
    RunResult,
    UnsupportedIOCType,
    build_udm_query,
)

__all__ = [
    "CHRONICLE_PLATFORM",
    "CHRONICLE_PROVIDER_KEY",
    "REGION_BASE_URLS",
    "SA_FIELD",
    "ChronicleAPIError",
    "ChronicleAuth",
    "ChronicleAuthError",
    "ChronicleClient",
    "ChronicleConfig",
    "ChronicleError",
    "GoogleServiceAccountAuth",
    "RetroHuntWorker",
    "RunResult",
    "StaticTokenAuth",
    "UdmSearchResult",
    "UnsupportedIOCType",
    "build_chronicle_client",
    "build_udm_query",
]
