"""Playbook execution engine — when/skip, retry, dry-run, audit, timeout."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from secops_term.core import audit as audit_mod
from secops_term.playbooks import engine as engine_mod
from secops_term.playbooks import schema


def _read_audit(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line:
                out.append(json.loads(line))
    return out


def _notify_step(
    *,
    id: str = "n1",
    when: str | None = None,
    summary: str = "{{ ioc.value }} hit",
    message: str = "details: {{ ioc.value }}",
    severity: str = "info",
) -> schema.NotifyStep:
    return schema.NotifyStep(
        id=id,
        type="notify",
        when=when,
        channel="slack:soc-alerts",
        summary=summary,
        message=message,
        severity=severity,  # type: ignore[arg-type]
    )


def _summarize_step(*, id: str = "s1", prompt: str = "summarize") -> schema.SummarizeStep:
    return schema.SummarizeStep(
        id=id,
        type="summarize",
        target="free_form",
        prompt=prompt,
    )


def _make_playbook(steps: list[schema.Step], **kwargs: Any) -> schema.Playbook:
    return schema.Playbook(
        name=kwargs.pop("name", "test"),
        description=None,
        trigger=schema.ManualTrigger(type="manual"),
        steps=steps,
        timeout_seconds=kwargs.pop("timeout_seconds", 300),
    )


# Stub runner factories


def _ok_runner(output: dict[str, Any]) -> engine_mod.StepRunner:
    async def _r(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        return output

    return _r


def _capturing_runner(captured: list[dict[str, Any]]):
    async def _r(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        captured.append(dict(rendered))
        return {"ok": True}

    return _r


def _retryable_runner(succeed_on_attempt: int):
    """Raises RetryableStepError until attempt ``succeed_on_attempt``."""
    counter = {"n": 0}

    async def _r(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        counter["n"] += 1
        if counter["n"] < succeed_on_attempt:
            raise engine_mod.RetryableStepError(f"attempt {counter['n']}")
        return {"attempt": counter["n"]}

    return _r, counter


# Basic execution


async def test_run_executes_each_step(tmp_root: Path) -> None:
    captured: list[dict[str, Any]] = []
    pb = _make_playbook([_notify_step(id="a"), _notify_step(id="b")])
    eng = engine_mod.Engine(
        runners={"notify": _capturing_runner(captured)},
        backoff_seconds=0,
    )
    run = await eng.run(pb, ioc={"value": "1.2.3.4"})
    assert run.overall_ok is True
    assert len(run.steps) == 2
    assert all(r.ok for r in run.steps)
    # Each step rendered the templated `summary` against ioc.value.
    assert captured[0]["summary"] == "1.2.3.4 hit"
    assert captured[1]["summary"] == "1.2.3.4 hit"


async def test_run_passes_step_output_to_subsequent_steps(tmp_root: Path) -> None:
    captured: list[dict[str, Any]] = []
    s1 = _notify_step(id="first", summary="first", message="first body")

    async def _first_runner(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        return {"hits": 5}

    s2 = _notify_step(
        id="second",
        summary="hit count: {{ steps.first.hits }}",
        message="body",
    )
    eng = engine_mod.Engine(
        runners={
            "notify": _make_routing_runner(
                {"first": _first_runner, "second": _capturing_runner(captured)}
            )
        },
        backoff_seconds=0,
    )
    pb = _make_playbook([s1, s2])
    run = await eng.run(pb, ioc={})
    assert run.overall_ok is True
    assert captured[0]["summary"] == "hit count: 5"


def _make_routing_runner(by_id: dict[str, engine_mod.StepRunner]) -> engine_mod.StepRunner:
    """Dispatch to a different stub per step id (for ordered tests)."""

    async def _r(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        return await by_id[step.id](step, rendered)

    return _r


# when:


async def test_when_falsy_skips_step(tmp_root: Path) -> None:
    captured: list[dict[str, Any]] = []
    s = _notify_step(when="{{ ioc.confidence > 90 }}")
    pb = _make_playbook([s])
    eng = engine_mod.Engine(
        runners={"notify": _capturing_runner(captured)},
        backoff_seconds=0,
    )
    run = await eng.run(pb, ioc={"confidence": 50})
    assert run.steps[0].skipped is True
    assert run.steps[0].ok is True
    assert captured == []


async def test_when_truthy_runs_step(tmp_root: Path) -> None:
    captured: list[dict[str, Any]] = []
    s = _notify_step(
        when="{{ ioc.confidence > 90 }}",
        summary="confident hit",
        message="see details",
    )
    pb = _make_playbook([s])
    eng = engine_mod.Engine(
        runners={"notify": _capturing_runner(captured)},
        backoff_seconds=0,
    )
    run = await eng.run(pb, ioc={"confidence": 99})
    assert run.steps[0].skipped is False
    assert run.steps[0].ok is True
    assert len(captured) == 1


async def test_when_sandbox_violation_fails_step(tmp_root: Path) -> None:
    s = _notify_step(when="{{ __import__('os').system('rm -rf /') }}")
    pb = _make_playbook([s])
    eng = engine_mod.Engine(runners={"notify": _ok_runner({})}, backoff_seconds=0)
    run = await eng.run(pb, ioc={})
    assert run.steps[0].ok is False
    assert "when:" in (run.steps[0].error or "")


# Retry


async def test_retryable_succeeds_within_budget(tmp_root: Path) -> None:
    runner, counter = _retryable_runner(succeed_on_attempt=3)
    pb = _make_playbook([_notify_step()])
    eng = engine_mod.Engine(
        runners={"notify": runner},
        backoff_seconds=0,
        max_attempts=3,
    )
    run = await eng.run(pb, ioc={"value": "x"})
    assert run.overall_ok is True
    assert run.steps[0].attempts == 3
    assert counter["n"] == 3


async def test_retryable_fails_after_budget(tmp_root: Path) -> None:
    runner, counter = _retryable_runner(succeed_on_attempt=99)
    pb = _make_playbook([_notify_step()])
    eng = engine_mod.Engine(
        runners={"notify": runner},
        backoff_seconds=0,
        max_attempts=3,
    )
    run = await eng.run(pb, ioc={"value": "x"})
    assert run.overall_ok is False
    assert run.steps[0].attempts == 3
    assert counter["n"] == 3


async def test_step_error_is_not_retried(tmp_root: Path) -> None:
    counter = {"n": 0}

    async def _r(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        counter["n"] += 1
        raise engine_mod.StepError("hard fail")

    pb = _make_playbook([_notify_step()])
    eng = engine_mod.Engine(
        runners={"notify": _r},
        backoff_seconds=0,
        max_attempts=3,
    )
    run = await eng.run(pb, ioc={"value": "x"})
    assert run.overall_ok is False
    assert counter["n"] == 1
    assert run.steps[0].attempts == 1


# Dry-run


async def test_dry_run_does_not_invoke_runner(tmp_root: Path) -> None:
    called = {"n": 0}

    async def _r(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        called["n"] += 1
        return {"called": True}

    pb = _make_playbook([_notify_step()])
    eng = engine_mod.Engine(runners={"notify": _r}, dry_run=True, backoff_seconds=0)
    run = await eng.run(pb, ioc={"value": "x"})
    assert called["n"] == 0
    assert run.dry_run is True
    assert run.steps[0].ok is True
    # Dry-run output exposes the rendered params for review.
    assert run.steps[0].output["dry_run"] is True
    assert run.steps[0].output["rendered"]["channel"] == "slack:soc-alerts"


# Audit


async def test_audit_emits_one_entry_per_step(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    pb = _make_playbook([_notify_step(id="a"), _notify_step(id="b")])
    eng = engine_mod.Engine(
        runners={"notify": _ok_runner({"ok": True})},
        audit_logger=log,
        backoff_seconds=0,
    )
    await eng.run(pb, ioc={"value": "x"})
    entries = _read_audit(log.path)
    assert len(entries) == 2
    assert all(e["entry"]["kind"] == "playbook_step" for e in entries)
    assert {e["entry"]["step_id"] for e in entries} == {"a", "b"}


async def test_audit_records_skipped_steps(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    pb = _make_playbook([_notify_step(when="{{ False }}")])
    eng = engine_mod.Engine(
        runners={"notify": _ok_runner({})},
        audit_logger=log,
        backoff_seconds=0,
    )
    await eng.run(pb, ioc={})
    e = _read_audit(log.path)[0]["entry"]
    assert e["skipped"] is True
    assert e["ok"] is True


async def test_audit_records_dry_run_flag(tmp_root: Path) -> None:
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    pb = _make_playbook([_notify_step()])
    eng = engine_mod.Engine(
        runners={"notify": _ok_runner({})},
        audit_logger=log,
        dry_run=True,
        backoff_seconds=0,
    )
    await eng.run(pb, ioc={"value": "x"})
    e = _read_audit(log.path)[0]["entry"]
    assert e["dry_run"] is True


# AI / untrusted


async def test_summarize_output_hidden_from_when(tmp_root: Path) -> None:
    """Brief §7.5 rule 1: AI step output may NOT gate later steps."""

    async def _summ_runner(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        # Real summarize runner returns {text, untrusted}; the stub
        # mirrors that shape. The engine flags untrusted_output via
        # isinstance(step, SummarizeStep), not by inspecting the dict.
        return {"text": "ai-derived analysis"}

    counter = {"n": 0}

    async def _notify_runner(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        counter["n"] += 1
        return {"ok": True}

    pb = _make_playbook(
        [
            _summarize_step(id="ai"),
            # The when expression references the summarize step's
            # output. The sandbox sees a `steps` dict that has
            # been stripped of untrusted entries — `steps.ai` is
            # not present, so `when:` should fail (NotFound).
            _notify_step(when='{{ steps.ai.text == "ai-derived analysis" }}'),
        ]
    )
    eng = engine_mod.Engine(
        runners={"summarize": _summ_runner, "notify": _notify_runner},
        backoff_seconds=0,
    )
    run = await eng.run(pb, ioc={})
    # First step succeeded.
    assert run.steps[0].ok is True
    assert run.steps[0].untrusted_output is True
    # Second step's when: blew up because steps.ai is hidden — engine
    # records it as a failed step (sandbox NotFound).
    assert run.steps[1].ok is False
    assert "ai" in (run.steps[1].error or "") or "NotFound" in (run.steps[1].error or "")
    assert counter["n"] == 0  # notify never ran


async def test_summarize_output_visible_in_notify_template(tmp_root: Path) -> None:
    """The same untrusted output is OK to flow into a notify template
    (display-only); the rule only blocks `when:` gating."""
    captured: list[dict[str, Any]] = []

    async def _summ(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        return {"text": "advisory text"}

    async def _notify(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        captured.append(dict(rendered))
        return {"ok": True}

    pb = _make_playbook(
        [
            _summarize_step(id="ai"),
            _notify_step(
                summary="{{ steps.ai.text }}",
                message="body",
            ),
        ]
    )
    eng = engine_mod.Engine(
        runners={"summarize": _summ, "notify": _notify},
        backoff_seconds=0,
    )
    run = await eng.run(pb, ioc={})
    assert run.overall_ok is True
    assert captured[0]["summary"] == "advisory text"


# Timeout


async def test_playbook_timeout(tmp_root: Path) -> None:
    async def _slow(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        await asyncio.sleep(2)
        return {}

    pb = _make_playbook([_notify_step()], timeout_seconds=1)
    eng = engine_mod.Engine(runners={"notify": _slow}, backoff_seconds=0)
    run = await eng.run(pb, ioc={"value": "x"})
    assert run.overall_ok is False
    assert any(s.step_id == "__timeout__" for s in run.steps)
    timeout_step = next(s for s in run.steps if s.step_id == "__timeout__")
    assert "1s timeout" in (timeout_step.error or "")


# Unknown step type


async def test_unknown_step_type_in_runner_map(tmp_root: Path) -> None:
    """Schema enforces step types statically, but the runner map is the
    runtime contract — missing entries surface a clean error."""
    pb = _make_playbook([_notify_step()])
    eng = engine_mod.Engine(runners={}, backoff_seconds=0)  # empty
    run = await eng.run(pb, ioc={"value": "x"})
    assert run.overall_ok is False
    assert "no runner registered" in (run.steps[0].error or "")


# PlaybookRun.errors helper


async def test_run_errors_lists_failed_steps_only() -> None:
    failing_runner_called = {"n": 0}

    async def _fail(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        failing_runner_called["n"] += 1
        raise engine_mod.StepError("boom")

    pb = _make_playbook(
        [
            _notify_step(id="ok_step"),
            _notify_step(id="fail_step"),
        ]
    )

    async def _route(step: schema.Step, rendered: dict[str, Any]) -> dict[str, Any]:
        if step.id == "ok_step":
            return {"ok": True}
        return await _fail(step, rendered)

    eng = engine_mod.Engine(runners={"notify": _route}, backoff_seconds=0)
    run = await eng.run(pb, ioc={"value": "x"})
    assert run.overall_ok is False
    assert len(run.errors) == 1
    assert run.errors[0].startswith("fail_step:")
