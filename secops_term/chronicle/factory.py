"""Build a :class:`ChronicleClient` from ``config.toml`` + keyring contents.

Per brief v3 §3.5.13: the ``[chronicle]`` block in ``config.toml`` carries
the non-secret bits (``customer_id``, ``region``, optional ``base_url``,
``allow_write``); the service-account JSON content lives in the keyring
under ``secops-term:chronicle:<instance>`` / ``service_account_json``.

This factory is the only sanctioned way for production code to assemble a
client. The CLI (``hunt run``, ``config test chronicle``) and the
orchestrator (``config test-all``) call it.

Returns ``None`` when no ``[chronicle]`` block exists at all — that's a
"not configured" signal, not an error. Raises :class:`ChronicleError` for
partial / malformed config or a missing keyring entry.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from secops_term.chronicle.auth import (
    ChronicleAuthError,
    GoogleServiceAccountAuth,
)
from secops_term.chronicle.client import (
    ChronicleClient,
    ChronicleConfig,
    ChronicleError,
)
from secops_term.core import config_io
from secops_term.core import secrets as secrets_mod

CHRONICLE_PROVIDER_KEY = "chronicle"
SA_FIELD = "service_account_json"


def build_chronicle_client(
    *,
    instance: str = "default",
    cfg_data: Mapping[str, Any] | None = None,
    credentials_factory: (Callable[[dict[str, Any], list[str]], Any] | None) = None,
) -> ChronicleClient | None:
    """Construct a :class:`ChronicleClient` from disk config + keyring secrets.

    - ``cfg_data`` overrides ``config_io.load_config()`` (tests).
    - ``credentials_factory`` is forwarded to
      :class:`GoogleServiceAccountAuth` so tests can bypass real
      ``google-auth``.

    Returns ``None`` if no ``[chronicle]`` block exists. Raises
    :class:`ChronicleError` on incomplete / malformed config or missing
    keyring entry.
    """
    data = cfg_data if cfg_data is not None else config_io.load_config()
    block = data.get("chronicle")
    if block is None:
        return None
    if not isinstance(block, Mapping):
        raise ChronicleError("config.toml `chronicle` block is not a table")

    customer_id = block.get("customer_id")
    region = block.get("region", "us")
    base_url = block.get("base_url")
    allow_write = bool(block.get("allow_write", False))

    if not isinstance(customer_id, str) or not customer_id.strip():
        raise ChronicleError("chronicle.customer_id missing or empty in config.toml")
    if not isinstance(region, str) or not region.strip():
        raise ChronicleError("chronicle.region missing or empty in config.toml")
    if base_url is not None and not isinstance(base_url, str):
        raise ChronicleError("chronicle.base_url must be a string when set")

    mgr = secrets_mod.get_manager()
    sa_value = mgr.get_secret(CHRONICLE_PROVIDER_KEY, instance, SA_FIELD)
    if not sa_value:
        raise ChronicleError(
            f"Chronicle service-account JSON not in keyring under "
            f"secops-term:{CHRONICLE_PROVIDER_KEY}:{instance}/{SA_FIELD}. "
            f"Run `secops-term config chronicle` to set it."
        )

    try:
        auth = GoogleServiceAccountAuth(sa_value, credentials_factory=credentials_factory)
    except ChronicleAuthError as exc:
        raise ChronicleError(f"could not build Chronicle auth: {exc}") from exc

    cfg = ChronicleConfig(
        customer_id=customer_id.strip(),
        region=region.strip(),
        base_url=base_url,
        allow_write=allow_write,
    )
    return ChronicleClient(cfg, auth=auth)


__all__ = [
    "CHRONICLE_PROVIDER_KEY",
    "SA_FIELD",
    "build_chronicle_client",
]
