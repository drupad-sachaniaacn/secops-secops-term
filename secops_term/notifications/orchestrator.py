"""Notification orchestrator — discover, build, and dispatch notifiers.

Per brief v3 §6.6 + §3.5.2:

- Walk ``[notifications.<notifier>.<instance>]`` blocks in ``config.toml``.
- Construct :class:`Notifier` instances via the registry's ``from_config``.
- Multi-instance is the norm (``slack:soc-alerts`` + ``slack:escalations``).
- Health targets surface for ``config test-all`` / ``doctor``.

The orchestrator is the boundary between the playbook engine (which
references channels by ``{notifier}:{instance}``) and the keyring +
config layers. Playbook code never reaches into notifications; it just
calls :func:`dispatch`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from secops_term.core import config_io
from secops_term.core.health import HealthStatus
from secops_term.core.registry import NotRegistered
from secops_term.notifications import NOTIFIERS, discover
from secops_term.notifications.base import (
    Notifier,
    NotifierError,
    NotifyPayload,
    NotifyResult,
)


@dataclass(frozen=True)
class ConfiguredNotifier:
    """One ``(notifier, instance, cfg)`` triple."""

    notifier: str
    instance: str
    cfg: Mapping[str, Any]

    @property
    def channel(self) -> str:
        """Playbook-style ``{notifier}:{instance}`` reference."""
        return f"{self.notifier}:{self.instance}"


def list_configured(
    *,
    cfg_data: Mapping[str, Any] | None = None,
) -> list[ConfiguredNotifier]:
    """Return every ``[notifications.<notifier>.<instance>]`` block."""
    if cfg_data is None:
        cfg_data = config_io.load_config()
    block = cfg_data.get("notifications") or {}
    if not isinstance(block, Mapping):
        return []
    out: list[ConfiguredNotifier] = []
    for notifier_name, instances in block.items():
        if not isinstance(notifier_name, str) or not isinstance(instances, Mapping):
            continue
        for instance_name, instance_cfg in instances.items():
            if not isinstance(instance_name, str) or not isinstance(instance_cfg, Mapping):
                continue
            out.append(
                ConfiguredNotifier(
                    notifier=notifier_name,
                    instance=instance_name,
                    cfg=dict(instance_cfg),
                )
            )
    return out


def build_notifier(target: ConfiguredNotifier) -> Notifier:
    """Construct one :class:`Notifier` from a configured triple.

    Raises :class:`NotifierError` if the registry doesn't know the name
    or the notifier's ``from_config`` rejects the cfg.
    """
    discover()
    try:
        cls = NOTIFIERS.get(target.notifier)
    except NotRegistered as exc:
        raise NotifierError(
            f"unknown notifier {target.notifier!r}; registered: {sorted(NOTIFIERS.keys())}"
        ) from exc
    instance = cls.from_config(target.instance, target.cfg)
    return instance


def build_by_channel(channel: str, *, cfg_data: Mapping[str, Any] | None = None) -> Notifier:
    """Build a single notifier referenced by ``{notifier}:{instance}``.

    The playbook engine calls this with the value from a ``notify`` step's
    ``channel:`` field. Raises :class:`NotifierError` if the channel isn't
    configured or the notifier rejects its cfg.
    """
    if ":" not in channel:
        raise NotifierError(f"channel {channel!r} must be of the form '<notifier>:<instance>'")
    notifier_name, _, instance_name = channel.partition(":")
    if not notifier_name or not instance_name:
        raise NotifierError(f"channel {channel!r} must be of the form '<notifier>:<instance>'")
    targets = list_configured(cfg_data=cfg_data)
    for tgt in targets:
        if tgt.notifier == notifier_name and tgt.instance == instance_name:
            return build_notifier(tgt)
    raise NotifierError(
        f"channel {channel!r} not configured "
        f"(no `[notifications.{notifier_name}.{instance_name}]` block)"
    )


async def dispatch(
    channel: str,
    payload: NotifyPayload,
    *,
    cfg_data: Mapping[str, Any] | None = None,
) -> NotifyResult:
    """Deliver ``payload`` to ``{notifier}:{instance}``.

    Returns the :class:`NotifyResult`; never raises on transport failure
    (that contract is part of the :class:`Notifier` Protocol).
    """
    notifier = build_by_channel(channel, cfg_data=cfg_data)
    return await notifier.send(payload)


def build_health_targets(
    *, cfg_data: Mapping[str, Any] | None = None
) -> list[tuple[Notifier, str]]:
    """Return ``(notifier, channel_label)`` pairs for ``health.run_all``.

    Same shape as :func:`secops_term.intel.orchestrator.build_health_targets`
    so ``config test-all`` and ``doctor`` can mix providers and notifiers
    in a single concurrent probe. The label is the playbook-style
    ``{notifier}:{instance}`` string.
    """
    targets = list_configured(cfg_data=cfg_data)
    out: list[tuple[Notifier, str]] = []
    for tgt in targets:
        try:
            notifier = build_notifier(tgt)
        except NotifierError:
            # Skip notifiers we can't build — the user will see the error
            # surfaced via `config test`. Doctor stays offline-friendly.
            continue
        out.append((notifier, tgt.channel))
    return out


async def health_check_all(*, cfg_data: Mapping[str, Any] | None = None) -> list[HealthStatus]:
    """Run ``health_check()`` on every configured notifier concurrently."""
    targets = build_health_targets(cfg_data=cfg_data)
    if not targets:
        return []
    return list(await asyncio.gather(*(notifier.health_check() for notifier, _ in targets)))


__all__ = [
    "ConfiguredNotifier",
    "build_by_channel",
    "build_health_targets",
    "build_notifier",
    "dispatch",
    "health_check_all",
    "list_configured",
]
