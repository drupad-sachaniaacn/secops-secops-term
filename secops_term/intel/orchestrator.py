"""Intel-pipeline orchestrator: drives configured providers + the store.

Phase 1 entry points:

- :func:`pull_all` — iterate every enabled ``(provider, instance)`` in
  ``config.toml``, instantiate via the registry, call ``pull()``, upsert
  results into the store, and return one :class:`PullResult` per pair.
- :func:`build_health_targets` — surface the same iteration as
  ``(provider, instance_label)`` tuples for the
  :func:`secops_term.core.health.run_all` runner so ``config test-all``
  doesn't have to duplicate the config-walking logic.

The CLI (:mod:`secops_term.cli`) is a thin wrapper over both of these.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from secops_term.core import config_io
from secops_term.core.registry import NotRegistered
from secops_term.intel import store as store_mod
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers.base import IntelProviderError


@dataclass(frozen=True)
class PullResult:
    """Outcome of pulling one ``(provider, instance)`` pair."""

    provider: str
    instance: str
    total: int  # records produced by the provider
    new: int  # first-observation IOCs
    reobserved: int  # repeat observations of an existing IOC
    error: str | None  # populated on failure; ``new`` and ``reobserved`` will be 0

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class _ConfiguredInstance:
    provider: str
    instance: str
    cfg: Mapping[str, Any]


def _walk_configured(
    *,
    provider_filter: str | None = None,
    instance_filter: str | None = None,
    cfg_data: Mapping[str, Any] | None = None,
) -> list[_ConfiguredInstance]:
    """Yield each enabled ``intel_providers.<provider>.<instance>`` block."""
    if cfg_data is None:
        cfg_data = config_io.load_config()
    intel_cfg = cfg_data.get("intel_providers") or {}
    if not isinstance(intel_cfg, Mapping):
        return []
    out: list[_ConfiguredInstance] = []
    for provider_name, instances in intel_cfg.items():
        if not isinstance(provider_name, str) or not isinstance(instances, Mapping):
            continue
        if provider_filter is not None and provider_name != provider_filter:
            continue
        for instance_name, instance_cfg in instances.items():
            if not isinstance(instance_name, str) or not isinstance(instance_cfg, Mapping):
                continue
            if instance_filter is not None and instance_name != instance_filter:
                continue
            enabled = instance_cfg.get("enabled", True)
            if not enabled:
                continue
            out.append(
                _ConfiguredInstance(
                    provider=provider_name,
                    instance=instance_name,
                    cfg=dict(instance_cfg),
                )
            )
    return out


async def pull_all(
    *,
    provider_filter: str | None = None,
    instance_filter: str | None = None,
    since: datetime | None = None,
    cfg_data: Mapping[str, Any] | None = None,
    store: store_mod.IOCStore | None = None,
) -> list[PullResult]:
    """Pull every configured provider+instance and upsert results into the store.

    Failures from one provider don't block the others — each pair gets its
    own :class:`PullResult` with the error captured.
    """
    targets = _walk_configured(
        provider_filter=provider_filter,
        instance_filter=instance_filter,
        cfg_data=cfg_data,
    )
    if not targets:
        return []
    own_store = store is None
    actual_store = store if store is not None else store_mod.get_default_store()
    try:
        results: list[PullResult] = []
        for tgt in targets:
            results.append(await _pull_one(tgt, since=since, store=actual_store))
        return results
    finally:
        if own_store:
            actual_store.database.close()


async def _pull_one(
    tgt: _ConfiguredInstance,
    *,
    since: datetime | None,
    store: store_mod.IOCStore,
) -> PullResult:
    try:
        cls = PROVIDERS.get(tgt.provider)
    except NotRegistered:
        return PullResult(
            tgt.provider,
            tgt.instance,
            0,
            0,
            0,
            f"provider {tgt.provider!r} not registered",
        )
    try:
        provider = cls.from_config(tgt.instance, tgt.cfg)
    except IntelProviderError as exc:
        return PullResult(tgt.provider, tgt.instance, 0, 0, 0, f"from_config: {exc}")
    except Exception as exc:
        return PullResult(
            tgt.provider,
            tgt.instance,
            0,
            0,
            0,
            f"from_config: {type(exc).__name__}: {exc}",
        )

    try:
        records = await provider.pull(since=since)
    except Exception as exc:
        return PullResult(
            tgt.provider,
            tgt.instance,
            0,
            0,
            0,
            f"pull: {type(exc).__name__}: {exc}",
        )

    new = 0
    reobserved = 0
    for record in records:
        try:
            _, is_new = store.upsert(record)
        except Exception:  # noqa: S112 - one bad record must not fail the batch
            continue
        if is_new:
            new += 1
        else:
            reobserved += 1
    return PullResult(
        provider=tgt.provider,
        instance=tgt.instance,
        total=len(records),
        new=new,
        reobserved=reobserved,
        error=None,
    )


def build_health_targets(
    *,
    provider_filter: str | None = None,
    instance_filter: str | None = None,
    cfg_data: Mapping[str, Any] | None = None,
    include_chronicle: bool = True,
) -> list[tuple[Any, str]]:
    """Return ``(provider_instance, instance_label)`` pairs for ``health.run_all``.

    Walks the intel-provider registry plus (when ``include_chronicle=True``)
    the top-level ``[chronicle]`` block. Skips entries where the provider
    isn't registered or ``from_config`` raises — those issues surface
    separately via doctor or pull.
    """
    targets = _walk_configured(
        provider_filter=provider_filter,
        instance_filter=instance_filter,
        cfg_data=cfg_data,
    )
    out: list[tuple[Any, str]] = []
    for tgt in targets:
        try:
            cls = PROVIDERS.get(tgt.provider)
        except NotRegistered:
            continue
        try:
            provider = cls.from_config(tgt.instance, tgt.cfg)
        except Exception:  # noqa: S112 - bad config is reported via doctor/pull, not health
            continue
        out.append((provider, tgt.instance))

    if include_chronicle and (provider_filter is None or provider_filter == "chronicle"):
        # Lazy import — keeps the orchestrator import light when Chronicle
        # is unconfigured, and avoids a circular import path through cli.
        try:
            from secops_term.chronicle import factory as chronicle_factory
            from secops_term.chronicle.client import ChronicleError
        except ImportError:  # pragma: no cover - chronicle package always shipped
            return out
        try:
            chronicle = chronicle_factory.build_chronicle_client(
                instance=instance_filter or "default",
                cfg_data=cfg_data,
            )
        except ChronicleError:
            chronicle = None
        if chronicle is not None:
            out.append((chronicle, instance_filter or "default"))

    if include_chronicle and (provider_filter is None or provider_filter == "vision_one"):
        try:
            from secops_term.trendmicro import factory as tm_factory
            from secops_term.trendmicro.vision_one import VisionOneError
        except ImportError:  # pragma: no cover - trendmicro package always shipped
            return out
        try:
            v1 = tm_factory.build_vision_one_client(
                instance=instance_filter or "default",
                cfg_data=cfg_data,
            )
        except VisionOneError:
            v1 = None
        if v1 is not None:
            out.append((v1, instance_filter or "default"))

    if include_chronicle and (provider_filter is None or provider_filter == "deep_security"):
        try:
            from secops_term.trendmicro import factory as tm_factory
            from secops_term.trendmicro.deep_security import DeepSecurityError
        except ImportError:  # pragma: no cover - trendmicro package always shipped
            return out
        try:
            ds = tm_factory.build_deep_security_client(
                instance=instance_filter or "default",
                cfg_data=cfg_data,
            )
        except DeepSecurityError:
            ds = None
        if ds is not None:
            out.append((ds, instance_filter or "default"))

    return out


def pull_all_sync(**kwargs: Any) -> list[PullResult]:
    """Sync wrapper for the CLI — runs ``pull_all`` in a fresh event loop."""
    return asyncio.run(pull_all(**kwargs))


__all__ = [
    "PullResult",
    "build_health_targets",
    "pull_all",
    "pull_all_sync",
]
