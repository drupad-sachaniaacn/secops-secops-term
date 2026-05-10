"""Step runners — concrete bindings for each step ``type``.

Per brief v3 §6.4. The :mod:`engine` is decoupled from these so tests
can inject stubs; production wires the real notification dispatch and
retro-hunt enqueue paths. ``api_call`` is a placeholder — Phase 5 only
allows read-only intel-provider enrichment, gated by an allowlist.
"""

from __future__ import annotations

from typing import Any

from secops_term.notifications import NotifyPayload
from secops_term.notifications import orchestrator as notify_orch
from secops_term.notifications.base import NotifierError
from secops_term.playbooks.engine import (
    RetryableStepError,
    StepError,
    StepRunner,
)
from secops_term.playbooks.schema import (
    ApiCallStep,
    NotifyStep,
    RetroHuntStep,
    Step,
    SummarizeStep,
)

# notify
# ------


async def notify_runner(step: Step, rendered: dict[str, Any]) -> dict[str, Any]:
    """Send a notification through the configured channel."""
    if not isinstance(step, NotifyStep):
        raise StepError(f"notify_runner got a {type(step).__name__}")
    payload = NotifyPayload(
        summary=str(rendered["summary"]),
        body=str(rendered["message"]),
        severity=rendered.get("severity", "info"),
        context={},
    )
    try:
        result = await notify_orch.dispatch(rendered["channel"], payload)
    except NotifierError as exc:
        raise StepError(f"notify: {exc}") from exc
    if not result.delivered:
        # Treat undelivered as retryable — most failures are transient
        # (rate limit, brief outage). The engine's retry budget caps
        # the blast radius.
        raise RetryableStepError(f"notify undelivered: {result.detail}")
    return {
        "delivered": result.delivered,
        "detail": result.detail,
        "latency_ms": result.latency_ms,
    }


# retro_hunt
# ----------


async def retro_hunt_runner(step: Step, rendered: dict[str, Any]) -> dict[str, Any]:
    """Enqueue a retro-hunt job for the triggering IOC."""
    if not isinstance(step, RetroHuntStep):
        raise StepError(f"retro_hunt_runner got a {type(step).__name__}")
    # IOC must be present in the engine context. The engine doesn't
    # expose ``ioc`` directly here — runners receive only the rendered
    # parameters — so this runner needs an injected IOC id. Wire that
    # in via partial / closure when constructing the runner map.
    raise StepError(
        "retro_hunt runner needs an IOC binding; see `build_runner_map(ioc=...)` in this module"
    )


# api_call (read-only intel enrichment placeholder)
# -------------------------------------------------


async def api_call_runner(step: Step, rendered: dict[str, Any]) -> dict[str, Any]:
    """Phase-5 surface: explicit allowlist, read-only only.

    Brief §13: write-capable api_call targets are gated behind a future
    ``allow_write`` flag. Until then, every ``api_call`` is rejected
    with a clear error so a playbook can't silently widen its blast
    radius by referencing a target the engine knows nothing about.
    """
    if not isinstance(step, ApiCallStep):
        raise StepError(f"api_call_runner got a {type(step).__name__}")
    raise StepError(
        f"api_call target {rendered['target']!r} not allowed in Phase 5 "
        f"(write-capable api_call gates behind allow_write — Phase 6+)"
    )


# summarize (AI bridge)
# ---------------------


async def summarize_runner(step: Step, rendered: dict[str, Any]) -> dict[str, Any]:
    """Run an AI summary via the bridge (Phase 4) — output is untrusted."""
    if not isinstance(step, SummarizeStep):
        raise StepError(f"summarize_runner got a {type(step).__name__}")
    # Lazy import — playbooks can be loaded / dry-run without the AI
    # bridge being available.
    from secops_term.ai.bridge import ClaudeNotFound, HeadlessClaudeBridge, resolve_claude_path
    from secops_term.ai.clipboard import ClipboardBridge
    from secops_term.ai.selector import (
        NoTransportAvailable,
        TransportCandidate,
        compose_bridge,
    )
    from secops_term.core import audit, paths

    paths.ensure_root_initialized()
    audit_logger = audit.AuditLogger()
    candidates: list[TransportCandidate] = []
    try:
        candidates.append(
            TransportCandidate(
                HeadlessClaudeBridge(claude_path=resolve_claude_path()),
                "claude-headless",
            )
        )
    except ClaudeNotFound:
        pass

    async def _no_paste(_msg: str) -> str:
        # Playbook context can't open a paste-modal; if headless isn't
        # available, the summarize step fails fast.
        raise NoTransportAvailable(
            "summarize requires Claude Code (`claude` on PATH); "
            "playbooks can't drive the clipboard fallback"
        )

    candidates.append(TransportCandidate(ClipboardBridge(response_provider=_no_paste), "clipboard"))

    try:
        bridge = await compose_bridge(candidates, audit_logger=audit_logger)
    except NoTransportAvailable as exc:
        raise StepError(f"summarize: {exc}") from exc
    try:
        text = await bridge.complete(rendered["prompt"])
    except Exception as exc:
        raise RetryableStepError(f"summarize bridge call failed: {exc}") from exc
    return {
        "text": text,
        "untrusted": True,  # advisory; the engine flags this via SummarizeStep isinstance.
    }


# Map builder
# -----------


def build_default_runners() -> dict[str, StepRunner]:
    """Return the production runner map.

    The ``retro_hunt`` runner needs an IOC binding, so callers that
    actually want retro-hunt execution should call
    :func:`build_runners_with_ioc` instead.
    """
    return {
        "notify": notify_runner,
        "retro_hunt": retro_hunt_runner,
        "api_call": api_call_runner,
        "summarize": summarize_runner,
    }


def build_runners_with_ioc(ioc_id: int) -> dict[str, StepRunner]:
    """Same as :func:`build_default_runners` but with retro_hunt bound.

    The ``ioc_id`` is closed over so ``retro_hunt`` knows which IOC to
    enqueue. Splitting this from the default map keeps "engine
    constructor" a pure function while letting trigger-based runs
    (``ioc_added`` triggers carry an IOC) wire the binding.
    """
    runners = build_default_runners()

    async def _retro(step: Step, rendered: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(step, RetroHuntStep):
            raise StepError(f"retro_hunt_runner got a {type(step).__name__}")
        # Lazy import to avoid pulling the whole intel/store dependency
        # chain into engine import time.
        from secops_term.intel import store as store_mod

        store = store_mod.get_default_store()
        try:
            job_id = store.enqueue_retro_hunt(ioc_id, rendered["platform"])
        except Exception as exc:  # store raises on missing IOC, etc.
            raise StepError(f"retro_hunt enqueue: {exc}") from exc
        return {
            "job_id": job_id,
            "ioc_id": ioc_id,
            "platform": rendered["platform"],
            "lookback_days": rendered["lookback_days"],
            "status": "queued",
        }

    runners["retro_hunt"] = _retro
    return runners


__all__ = [
    "api_call_runner",
    "build_default_runners",
    "build_runners_with_ioc",
    "notify_runner",
    "retro_hunt_runner",
    "summarize_runner",
]
