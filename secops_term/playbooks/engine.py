"""Playbook execution engine.

Per brief v3 §6.4. Runs a :class:`Playbook` against a context, with:

- All ``{{ }}`` expressions evaluated through the §3.5.7 sandbox.
- Per-step retry: 3 attempts, exponential backoff, retryable HTTP only.
- Per-step audit entries (``kind="playbook_step"``).
- Hard playbook timeout (default 5 min, configurable in YAML).
- ``--dry-run`` mode that walks the same control flow without making
  any network call or notifier dispatch.
- AI step outputs flagged untrusted; the sandbox refuses to expose
  them to other steps' ``when:`` expressions (brief §7.5).

The engine is decoupled from concrete clients — it dispatches through
``StepRunner`` callables registered for each step ``type``. Tests can
swap in stub runners; production wires the real notification /
retro-hunt / api-call paths.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any

from secops_term.core import audit as audit_mod
from secops_term.playbooks import sandbox
from secops_term.playbooks.schema import (
    ApiCallStep,
    NotifyStep,
    Playbook,
    RetroHuntStep,
    Step,
    SummarizeStep,
)
from secops_term.playbooks.schema import (
    SummarizeStep as _SummarizeStep,  # alias for `isinstance` clarity
)


class PlaybookRuntimeError(Exception):
    """Engine-level failure (timeout, sandbox violation in `when:`, etc.)."""


# Public records — what the CLI / TUI display after a run.


@dataclass(frozen=True)
class StepResult:
    """One step's outcome."""

    step_id: str
    type: str
    skipped: bool
    ok: bool
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    attempts: int = 1
    latency_ms: float = 0.0
    untrusted_output: bool = False


@dataclass(frozen=True)
class PlaybookRun:
    """Aggregate result of executing a playbook end-to-end."""

    playbook: str
    dry_run: bool
    steps: list[StepResult]
    overall_ok: bool
    total_latency_ms: float

    @property
    def errors(self) -> list[str]:
        return [
            f"{s.step_id}: {s.error}"
            for s in self.steps
            if not s.skipped and not s.ok and s.error is not None
        ]


# StepRunner contract — concrete implementations live in `runners.py`.


StepRunner = Callable[[Step, dict[str, Any]], Awaitable[dict[str, Any]]]


# Engine
# ------

_RETRYABLE_DEFAULT = 3


@dataclass
class Engine:
    """Stateful executor: knows runners, audit, dry-run mode."""

    runners: Mapping[str, StepRunner]
    audit_logger: audit_mod.AuditLogger | None = None
    dry_run: bool = False
    max_attempts: int = _RETRYABLE_DEFAULT
    backoff_seconds: float = 0.2

    async def run(
        self,
        playbook: Playbook,
        *,
        ioc: Mapping[str, Any] | None = None,
    ) -> PlaybookRun:
        """Execute ``playbook`` against an initial context.

        ``ioc`` is the triggering IOC dict (when applicable). For
        ``manual`` triggers it can be ``None`` or a placeholder.
        """
        started = perf_counter()
        # Sandbox context — `ioc` and `steps` are the only allowed
        # top-level names.
        ctx_ioc: dict[str, Any] = dict(ioc) if ioc is not None else {}
        ctx_steps: dict[str, Any] = {}
        # Track which step ids produced AI-derived (untrusted) output.
        # The sandbox-context filter for `when:` strips these.
        untrusted_ids: set[str] = set()
        results: list[StepResult] = []

        deadline_s = playbook.timeout_seconds
        try:
            await asyncio.wait_for(
                self._run_steps(playbook, ctx_ioc, ctx_steps, untrusted_ids, results),
                timeout=deadline_s,
            )
        except TimeoutError:
            results.append(
                StepResult(
                    step_id="__timeout__",
                    type="timeout",
                    skipped=False,
                    ok=False,
                    error=f"playbook exceeded {deadline_s}s timeout",
                    latency_ms=(perf_counter() - started) * 1000.0,
                )
            )

        elapsed_ms = (perf_counter() - started) * 1000.0
        overall = all(r.ok for r in results if not r.skipped)
        return PlaybookRun(
            playbook=playbook.name,
            dry_run=self.dry_run,
            steps=results,
            overall_ok=overall,
            total_latency_ms=elapsed_ms,
        )

    async def _run_steps(
        self,
        playbook: Playbook,
        ctx_ioc: dict[str, Any],
        ctx_steps: dict[str, Any],
        untrusted_ids: set[str],
        results: list[StepResult],
    ) -> None:
        for step in playbook.steps:
            # Build a sandbox context view that hides untrusted AI
            # outputs from `when:` evaluation. This is the brief §7.5
            # rule made operational: an AI-step's output may flow into
            # later notify-step text (which goes through the sandbox
            # too), but it must not gate control flow.
            when_ctx = self._sanitize_for_when(ctx_ioc, ctx_steps, untrusted_ids)

            if step.when is not None:
                try:
                    cond = _evaluate_when(step.when, when_ctx)
                except sandbox.SandboxError as exc:
                    results.append(
                        StepResult(
                            step_id=step.id,
                            type=step.type,
                            skipped=False,
                            ok=False,
                            error=f"when: {type(exc).__name__}: {exc}",
                        )
                    )
                    self._audit_step(playbook, step, ok=False, skipped=False, error=str(exc))
                    return
                if not cond:
                    results.append(
                        StepResult(
                            step_id=step.id,
                            type=step.type,
                            skipped=True,
                            ok=True,
                        )
                    )
                    self._audit_step(playbook, step, ok=True, skipped=True)
                    continue

            full_ctx = {"ioc": ctx_ioc, "steps": ctx_steps}
            rendered = self._render_params(step, full_ctx)
            result = await self._run_one(step, rendered)
            results.append(result)
            self._audit_step(
                playbook,
                step,
                ok=result.ok,
                skipped=False,
                error=result.error,
                latency_ms=result.latency_ms,
                attempts=result.attempts,
            )
            if result.ok:
                ctx_steps[step.id] = result.output
                if result.untrusted_output:
                    untrusted_ids.add(step.id)

    async def _run_one(self, step: Step, rendered: dict[str, Any]) -> StepResult:
        if step.type not in self.runners:
            return StepResult(
                step_id=step.id,
                type=step.type,
                skipped=False,
                ok=False,
                error=f"no runner registered for step type {step.type!r}",
            )
        runner = self.runners[step.type]

        if self.dry_run:
            return StepResult(
                step_id=step.id,
                type=step.type,
                skipped=False,
                ok=True,
                output={"dry_run": True, "rendered": rendered},
                attempts=1,
                untrusted_output=isinstance(step, _SummarizeStep),
            )

        last_error: str | None = None
        attempts = 0
        backoff = self.backoff_seconds
        started = perf_counter()
        while attempts < self.max_attempts:
            attempts += 1
            try:
                output = await runner(step, rendered)
            except RetryableStepError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempts < self.max_attempts:
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                break
            except StepError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                break
            except Exception as exc:
                # Non-retryable; bubble up with class name preserved.
                last_error = f"{type(exc).__name__}: {exc}"
                break
            return StepResult(
                step_id=step.id,
                type=step.type,
                skipped=False,
                ok=True,
                output=output,
                attempts=attempts,
                latency_ms=(perf_counter() - started) * 1000.0,
                untrusted_output=isinstance(step, _SummarizeStep),
            )
        return StepResult(
            step_id=step.id,
            type=step.type,
            skipped=False,
            ok=False,
            error=last_error,
            attempts=attempts,
            latency_ms=(perf_counter() - started) * 1000.0,
        )

    def _render_params(self, step: Step, ctx: Mapping[str, Any]) -> dict[str, Any]:
        """Sandbox-render every templated string field on ``step``."""
        if isinstance(step, ApiCallStep):
            return {
                "target": step.target,
                "action": step.action,
                "params": _render_dict(step.params, ctx),
            }
        if isinstance(step, RetroHuntStep):
            return {
                "platform": step.platform,
                "lookback_days": step.lookback_days,
            }
        if isinstance(step, NotifyStep):
            return {
                "channel": step.channel,
                "summary": sandbox.evaluate_template(step.summary, ctx),
                "message": sandbox.evaluate_template(step.message, ctx),
                "severity": step.severity,
            }
        if isinstance(step, SummarizeStep):
            return {
                "target": step.target,
                "prompt": sandbox.evaluate_template(step.prompt, ctx),
            }
        # exhaustive — Step is a closed Union; mypy will catch a new variant
        raise PlaybookRuntimeError(f"unhandled step type for rendering: {type(step).__name__}")

    def _audit_step(
        self,
        playbook: Playbook,
        step: Step,
        *,
        ok: bool,
        skipped: bool,
        error: str | None = None,
        latency_ms: float | None = None,
        attempts: int | None = None,
    ) -> None:
        if self.audit_logger is None:
            return
        entry: dict[str, Any] = {
            "kind": "playbook_step",
            "playbook": playbook.name,
            "step_id": step.id,
            "step_type": step.type,
            "skipped": skipped,
            "ok": ok,
            "dry_run": self.dry_run,
        }
        if error is not None:
            entry["error"] = error[:300]
        if latency_ms is not None:
            entry["latency_ms"] = round(latency_ms, 3)
        if attempts is not None:
            entry["attempts"] = attempts
        with contextlib.suppress(Exception):
            self.audit_logger.emit(entry)

    @staticmethod
    def _sanitize_for_when(
        ioc: dict[str, Any],
        steps: dict[str, Any],
        untrusted_ids: set[str],
    ) -> dict[str, Any]:
        """Build a sandbox context that hides untrusted-step outputs.

        This is the operational form of brief §7.5 rule 1: AI step
        outputs are display-only and may NOT drive control flow. We
        keep them in the full ``steps`` dict (so subsequent ``notify``
        templates can reference them — they go through the sandbox
        too, but `when:` is the gating decision we're protecting), but
        the version we hand to ``when:`` evaluation strips them out.
        """
        if not untrusted_ids:
            return {"ioc": ioc, "steps": steps}
        clean_steps = {k: v for k, v in steps.items() if k not in untrusted_ids}
        return {"ioc": ioc, "steps": clean_steps}


def _evaluate_when(when_str: str, ctx: Mapping[str, Any]) -> Any:
    """Evaluate a ``when:`` expression. Strips a single ``{{ ... }}`` envelope.

    Brief §6.4 examples wrap the expression in ``{{ ... }}``; that's the
    user-facing convention. Internally we want a single expression
    (not a template) so we can use the result's truthiness directly.
    Bare expressions (no envelope) are also accepted for terseness.
    """
    s = when_str.strip()
    if s.startswith("{{") and s.endswith("}}"):
        s = s[2:-2].strip()
    return sandbox.evaluate(s, ctx)


def _render_dict(d: Mapping[str, Any], ctx: Mapping[str, Any]) -> dict[str, Any]:
    """Render every string value in ``d`` via the sandbox; recurse into dicts/lists."""
    out: dict[str, Any] = {}
    for k, v in d.items():
        out[k] = _render_value(v, ctx)
    return out


def _render_value(v: Any, ctx: Mapping[str, Any]) -> Any:
    if isinstance(v, str):
        return sandbox.evaluate_template(v, ctx)
    if isinstance(v, dict):
        return _render_dict(v, ctx)
    if isinstance(v, list):
        return [_render_value(x, ctx) for x in v]
    return v


# Step error classes — runners raise these; engine handles retry policy.


class StepError(Exception):
    """Non-retryable failure inside a step runner."""


class RetryableStepError(StepError):
    """Retryable failure (transient network / 5xx). Engine re-runs up to ``max_attempts``."""


__all__ = [
    "Engine",
    "PlaybookRun",
    "PlaybookRuntimeError",
    "RetryableStepError",
    "StepError",
    "StepResult",
    "StepRunner",
]
