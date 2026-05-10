"""Pydantic v2 schema for playbook YAML files.

Per brief v3 §6.4. Models a playbook as a strict tree of typed
``Trigger`` / ``Step`` objects so the engine never sees raw YAML.
Validation happens *before* execution — a malformed playbook is a
load-time error, not a runtime mid-execution failure.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Triggers
# --------

# Per brief: MVP triggers are ``ioc_added``, ``manual``, ``scheduled``.
# Each is a discriminated union member with a ``type`` literal.


class IocAddedTrigger(BaseModel):
    """Fires when a new IOC is upserted into the local store."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["ioc_added"]
    filter: dict[str, Any] | None = None


class ManualTrigger(BaseModel):
    """Operator-invoked playbook (CLI / TUI button)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["manual"]


class ScheduledTrigger(BaseModel):
    """Cron-like schedule. Phase 5 doesn't yet wire a scheduler — the
    field exists so playbooks can declare the intent and the runner can
    refuse to schedule-fire until Phase 6 ships the cron worker."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["scheduled"]
    cron: str = Field(min_length=1)


Trigger = Annotated[
    IocAddedTrigger | ManualTrigger | ScheduledTrigger,
    Field(discriminator="type"),
]


# Steps
# -----


class _BaseStep(BaseModel):
    """Common fields for every step type."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(
        min_length=1,
        max_length=64,
        description="Unique-within-playbook step id; referenced by `{{ steps.<id>.* }}`.",
    )
    when: str | None = None
    """Optional sandbox expression — step runs only if it evaluates truthy."""

    @field_validator("id")
    @classmethod
    def _valid_step_id(cls, v: str) -> str:
        # Identifier-shaped: letters / digits / underscore. Avoids quoting
        # surprises in `{{ steps.<id>.* }}` references downstream.
        if not v.replace("_", "").isalnum():
            raise ValueError(f"step id {v!r} must contain only letters, digits, and underscores")
        return v


class ApiCallStep(_BaseStep):
    """Generic API call into a registered intel/Chronicle/V1 client.

    The engine looks up ``target`` against a small allowlist of safe-by-design
    callable surfaces. Phase 5 wires only ``intel_provider:<name>:<instance>``
    (read-only enrichment); ``api_call`` to write-capable targets is gated
    behind a future ``allow_write`` config flag (brief §13).
    """

    type: Literal["api_call"]
    target: str = Field(min_length=1)
    action: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)


class RetroHuntStep(_BaseStep):
    """Enqueue a retro-hunt job for the triggering IOC."""

    type: Literal["retro_hunt"]
    platform: Literal["chronicle", "vision_one"]
    lookback_days: int = Field(default=30, ge=1, le=365)


class NotifyStep(_BaseStep):
    """Send a notification through a configured channel.

    Per brief §6.6 channels are referenced as ``{notifier}:{instance}``.
    The notifier orchestrator (:mod:`secops_term.notifications.orchestrator`)
    resolves the channel; the engine never sees raw URLs or webhook keys.
    """

    type: Literal["notify"]
    channel: str = Field(
        min_length=3,
        pattern=r"^[a-z_]+:[A-Za-z0-9_-]+$",
        description="Format: '<notifier>:<instance>' (e.g. 'slack:soc-alerts').",
    )
    summary: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=8000)
    severity: Literal["info", "warn", "error"] = "info"


class SummarizeStep(_BaseStep):
    """AI-summary step (advisory, display-only).

    Per brief §7.5: AI output may flow into ``notify`` (display only) but
    NEVER into ``when:`` conditions or write-capable step parameters.
    The engine enforces this at execution time — the result of a
    ``summarize`` step is added to ``steps.<id>.text`` but a separate
    flag marks it as untrusted; the sandbox refuses to expose it to
    other steps' ``when:`` expressions.
    """

    type: Literal["summarize"]
    target: Literal["udm", "tmv1", "free_form"] = "free_form"
    prompt: str = Field(min_length=1, max_length=4000)


Step = Annotated[
    ApiCallStep | RetroHuntStep | NotifyStep | SummarizeStep,
    Field(discriminator="type"),
]


# Playbook
# --------


class Playbook(BaseModel):
    """Top-level playbook document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=80)
    description: str | None = None
    trigger: Trigger
    steps: list[Step] = Field(min_length=1, max_length=50)
    timeout_seconds: int = Field(default=300, ge=1, le=1800)
    """Hard playbook timeout (brief §6.4: 5 min default, configurable)."""

    @field_validator("steps")
    @classmethod
    def _unique_step_ids(cls, v: list[Step]) -> list[Step]:
        ids = [s.id for s in v]
        if len(ids) != len(set(ids)):
            seen: set[str] = set()
            dupes: set[str] = set()
            for i in ids:
                if i in seen:
                    dupes.add(i)
                seen.add(i)
            raise ValueError(f"duplicate step ids: {sorted(dupes)}")
        return v


__all__ = [
    "ApiCallStep",
    "IocAddedTrigger",
    "ManualTrigger",
    "NotifyStep",
    "Playbook",
    "RetroHuntStep",
    "ScheduledTrigger",
    "Step",
    "SummarizeStep",
    "Trigger",
]
