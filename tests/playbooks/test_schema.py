"""Pydantic schema for playbook YAML — strict validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from secops_term.playbooks import schema


def _minimal_data(steps: list[dict] | None = None) -> dict:
    return {
        "name": "test-playbook",
        "trigger": {"type": "manual"},
        "steps": steps
        or [
            {
                "id": "s1",
                "type": "notify",
                "channel": "slack:soc-alerts",
                "summary": "x",
                "message": "y",
            }
        ],
    }


# Top-level


def test_minimal_playbook_validates() -> None:
    pb = schema.Playbook.model_validate(_minimal_data())
    assert pb.name == "test-playbook"
    assert isinstance(pb.trigger, schema.ManualTrigger)
    assert len(pb.steps) == 1


def test_unknown_top_level_field_rejected() -> None:
    data = _minimal_data()
    data["unknown"] = "field"
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)


def test_default_timeout_is_5min() -> None:
    pb = schema.Playbook.model_validate(_minimal_data())
    assert pb.timeout_seconds == 300


def test_timeout_bounded() -> None:
    data = _minimal_data()
    data["timeout_seconds"] = 0
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)
    data["timeout_seconds"] = 9999
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)


# Triggers


def test_ioc_added_trigger_with_filter() -> None:
    data = _minimal_data()
    data["trigger"] = {"type": "ioc_added", "filter": {"confidence_gte": 80}}
    pb = schema.Playbook.model_validate(data)
    assert isinstance(pb.trigger, schema.IocAddedTrigger)
    assert pb.trigger.filter == {"confidence_gte": 80}


def test_scheduled_trigger_requires_cron() -> None:
    data = _minimal_data()
    data["trigger"] = {"type": "scheduled"}
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)


def test_unknown_trigger_type_rejected() -> None:
    data = _minimal_data()
    data["trigger"] = {"type": "webhook"}
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)


# Steps


def test_notify_step_validates() -> None:
    pb = schema.Playbook.model_validate(_minimal_data())
    notify = pb.steps[0]
    assert isinstance(notify, schema.NotifyStep)
    assert notify.severity == "info"  # default


def test_notify_channel_format_enforced() -> None:
    data = _minimal_data(
        [
            {
                "id": "s1",
                "type": "notify",
                "channel": "no-instance",
                "summary": "x",
                "message": "y",
            }
        ]
    )
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)


def test_step_id_must_be_identifier_shaped() -> None:
    data = _minimal_data(
        [
            {
                "id": "has spaces",
                "type": "notify",
                "channel": "slack:x",
                "summary": "a",
                "message": "b",
            }
        ]
    )
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)


def test_duplicate_step_ids_rejected() -> None:
    data = _minimal_data(
        [
            {
                "id": "s",
                "type": "notify",
                "channel": "slack:x",
                "summary": "a",
                "message": "b",
            },
            {
                "id": "s",
                "type": "notify",
                "channel": "slack:y",
                "summary": "c",
                "message": "d",
            },
        ]
    )
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)


def test_retro_hunt_step_defaults() -> None:
    data = _minimal_data([{"id": "r", "type": "retro_hunt", "platform": "chronicle"}])
    pb = schema.Playbook.model_validate(data)
    rh = pb.steps[0]
    assert isinstance(rh, schema.RetroHuntStep)
    assert rh.lookback_days == 30


def test_retro_hunt_platform_enum() -> None:
    data = _minimal_data([{"id": "r", "type": "retro_hunt", "platform": "splunk"}])
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)


def test_summarize_step() -> None:
    data = _minimal_data([{"id": "s", "type": "summarize", "prompt": "summarize the alert"}])
    pb = schema.Playbook.model_validate(data)
    s = pb.steps[0]
    assert isinstance(s, schema.SummarizeStep)
    assert s.target == "free_form"


def test_api_call_step() -> None:
    data = _minimal_data(
        [
            {
                "id": "a",
                "type": "api_call",
                "target": "virustotal",
                "action": "get_file_report",
                "params": {"hash": "abc"},
            }
        ]
    )
    pb = schema.Playbook.model_validate(data)
    api = pb.steps[0]
    assert isinstance(api, schema.ApiCallStep)
    assert api.params == {"hash": "abc"}


def test_when_field_optional() -> None:
    data = _minimal_data(
        [
            {
                "id": "s1",
                "type": "notify",
                "when": "{{ ioc.confidence > 50 }}",
                "channel": "slack:x",
                "summary": "a",
                "message": "b",
            }
        ]
    )
    pb = schema.Playbook.model_validate(data)
    assert pb.steps[0].when is not None


def test_unknown_step_type_rejected() -> None:
    data = _minimal_data([{"id": "s", "type": "exploit", "params": {}}])
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)


def test_must_have_at_least_one_step() -> None:
    data = _minimal_data([])
    data["steps"] = []
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)


def test_extra_fields_on_step_rejected() -> None:
    data = _minimal_data(
        [
            {
                "id": "s",
                "type": "notify",
                "channel": "slack:x",
                "summary": "a",
                "message": "b",
                "extra": "leaked",
            }
        ]
    )
    with pytest.raises(ValidationError):
        schema.Playbook.model_validate(data)
