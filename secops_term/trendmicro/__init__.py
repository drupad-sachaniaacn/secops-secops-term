"""Trend Micro Vision One (XDR) and Deep Security clients.

- V1 (Phase 3.1): :mod:`secops_term.trendmicro.vision_one` — Search +
  Workbench + health probe; region locked to US.
- DS (Phase 3.2): :mod:`secops_term.trendmicro.deep_security` — read-only
  alerts + agent status (DSaaS or on-prem).

Shared factory: :mod:`secops_term.trendmicro.factory` walks
``config.toml`` + the keyring to assemble production clients.
"""

from secops_term.trendmicro.deep_security import (
    DSAAS_BASE_URL,
    DeepSecurityAPIError,
    DeepSecurityClient,
    DeepSecurityConfig,
    DeepSecurityError,
    DeploymentType,
    DSAgentsResult,
    DSAlertsResult,
)
from secops_term.trendmicro.factory import (
    DS_KEY_FIELD,
    DS_PROVIDER_KEY,
    V1_PROVIDER_KEY,
    V1_TOKEN_FIELD,
    build_deep_security_client,
    build_vision_one_client,
)
from secops_term.trendmicro.vision_one import (
    VISION_ONE_BASE_URL,
    V1SearchResult,
    V1WorkbenchAlertsResult,
    VisionOneAPIError,
    VisionOneClient,
    VisionOneConfig,
    VisionOneError,
)

__all__ = [
    "DSAAS_BASE_URL",
    "DS_KEY_FIELD",
    "DS_PROVIDER_KEY",
    "V1_PROVIDER_KEY",
    "V1_TOKEN_FIELD",
    "VISION_ONE_BASE_URL",
    "DSAgentsResult",
    "DSAlertsResult",
    "DeepSecurityAPIError",
    "DeepSecurityClient",
    "DeepSecurityConfig",
    "DeepSecurityError",
    "DeploymentType",
    "V1SearchResult",
    "V1WorkbenchAlertsResult",
    "VisionOneAPIError",
    "VisionOneClient",
    "VisionOneConfig",
    "VisionOneError",
    "build_deep_security_client",
    "build_vision_one_client",
]
