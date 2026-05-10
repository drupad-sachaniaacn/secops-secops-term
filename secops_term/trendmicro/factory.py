"""Build :class:`VisionOneClient` (and Phase 3.2: :class:`DeepSecurityClient`)
from ``config.toml`` + keyring contents.

Per brief v3 §3.5.13: the per-tenant secrets live in the keyring; the
non-secret config (allow_write toggle, optional base_url override) lives
in ``config.toml``. Vision One's region is locked to US, so the base URL
is hardcoded unless a deployment explicitly overrides it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from secops_term.core import config_io
from secops_term.core import secrets as secrets_mod
from secops_term.trendmicro.deep_security import (
    DSAAS_BASE_URL,
    DeepSecurityClient,
    DeepSecurityConfig,
    DeepSecurityError,
    DeploymentType,
)
from secops_term.trendmicro.vision_one import (
    VISION_ONE_BASE_URL,
    VisionOneClient,
    VisionOneConfig,
    VisionOneError,
)

V1_PROVIDER_KEY = "vision_one"
V1_TOKEN_FIELD = "api_token"  # noqa: S105 - field name, not a credential

DS_PROVIDER_KEY = "deep_security"
DS_KEY_FIELD = "api_key"


def build_vision_one_client(
    *,
    instance: str = "default",
    cfg_data: Mapping[str, Any] | None = None,
) -> VisionOneClient | None:
    """Construct a :class:`VisionOneClient` from disk config + keyring secret.

    Returns ``None`` if no ``[vision_one]`` block exists. Raises
    :class:`VisionOneError` on incomplete config or missing keyring entry.
    """
    data = cfg_data if cfg_data is not None else config_io.load_config()
    block = data.get("vision_one")
    if block is None:
        return None
    if not isinstance(block, Mapping):
        raise VisionOneError("config.toml `vision_one` block is not a table")

    base_url = block.get("base_url", VISION_ONE_BASE_URL)
    allow_write = bool(block.get("allow_write", False))

    if not isinstance(base_url, str) or not base_url.strip():
        raise VisionOneError("vision_one.base_url must be a non-empty string")

    mgr = secrets_mod.get_manager()
    token = mgr.get_secret(V1_PROVIDER_KEY, instance, V1_TOKEN_FIELD)
    if not token:
        raise VisionOneError(
            f"Vision One API token not in keyring under "
            f"secops-term:{V1_PROVIDER_KEY}:{instance}/{V1_TOKEN_FIELD}. "
            f"Run `secops-term config vision-one` to set it."
        )

    cfg = VisionOneConfig(
        api_token=token,
        base_url=base_url.strip(),
        allow_write=allow_write,
    )
    return VisionOneClient(cfg)


def build_deep_security_client(
    *,
    instance: str = "default",
    cfg_data: Mapping[str, Any] | None = None,
) -> DeepSecurityClient | None:
    """Construct a :class:`DeepSecurityClient` from disk config + keyring secret.

    Returns ``None`` if no ``[deep_security]`` block exists. Raises
    :class:`DeepSecurityError` on incomplete config or missing keyring entry.

    The block accepts ``base_url`` (required, no default — DSaaS users
    point at ``https://app.deepsecurity.trendmicro.com``, on-prem points
    at their DSM URL), and optional ``deployment_type`` (``"dsaas"`` or
    ``"on_prem"``, default ``"dsaas"``).
    """
    data = cfg_data if cfg_data is not None else config_io.load_config()
    block = data.get("deep_security")
    if block is None:
        return None
    if not isinstance(block, Mapping):
        raise DeepSecurityError("config.toml `deep_security` block is not a table")

    base_url = block.get("base_url", DSAAS_BASE_URL)
    if not isinstance(base_url, str) or not base_url.strip():
        raise DeepSecurityError("deep_security.base_url must be a non-empty string")
    deployment_raw = block.get("deployment_type", "dsaas")
    if not isinstance(deployment_raw, str):
        raise DeepSecurityError("deep_security.deployment_type must be a string when set")
    if deployment_raw not in ("dsaas", "on_prem"):
        raise DeepSecurityError(
            f"deep_security.deployment_type must be 'dsaas' or 'on_prem', got {deployment_raw!r}"
        )
    deployment_type: DeploymentType = "dsaas" if deployment_raw == "dsaas" else "on_prem"

    mgr = secrets_mod.get_manager()
    api_key = mgr.get_secret(DS_PROVIDER_KEY, instance, DS_KEY_FIELD)
    if not api_key:
        raise DeepSecurityError(
            f"Deep Security API key not in keyring under "
            f"secops-term:{DS_PROVIDER_KEY}:{instance}/{DS_KEY_FIELD}. "
            f"Run `secops-term config deep-security` to set it."
        )

    cfg = DeepSecurityConfig(
        api_key=api_key,
        base_url=base_url.strip(),
        deployment_type=deployment_type,
    )
    return DeepSecurityClient(cfg)


__all__ = [
    "DS_KEY_FIELD",
    "DS_PROVIDER_KEY",
    "V1_PROVIDER_KEY",
    "V1_TOKEN_FIELD",
    "build_deep_security_client",
    "build_vision_one_client",
]
