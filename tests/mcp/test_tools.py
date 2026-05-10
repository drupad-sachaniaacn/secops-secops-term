"""MCP tool implementations — pure-Python async functions."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secops_term.core import db as core_db
from secops_term.intel import store as store_mod
from secops_term.intel.providers.base import IntelRecord
from secops_term.mcp import tools as tools_mod

# search_iocs


@pytest.fixture
def store_with_data(migrated_db: core_db.Database) -> Iterator[store_mod.IOCStore]:
    store = store_mod.IOCStore(migrated_db)
    now = datetime.now(UTC)
    rec_a = IntelRecord(
        source="abuse_ch:default",
        type="ipv4",
        value="1.2.3.4",
        fetched_at=now,
        confidence=80,
        context="malicious",
        source_ref=None,
        tags=("malware",),
    )
    rec_b = IntelRecord(
        source="otx:default",
        type="domain",
        value="evil.com",
        fetched_at=now,
        confidence=60,
        context="phishing",
        source_ref=None,
        tags=(),
    )
    store.upsert(rec_a)
    store.upsert(rec_b)
    yield store


async def test_search_iocs_returns_matches(
    store_with_data: store_mod.IOCStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(store_mod, "get_default_store", lambda: store_with_data)
    spec = tools_mod.MCP_TOOLS["search_iocs"]
    result = await spec.handler({"query": "1.2.3.4", "limit": 10})
    assert result["count"] == 1
    assert result["matches"][0]["value"] == "1.2.3.4"
    assert result["matches"][0]["type"] == "ipv4"


async def test_search_iocs_requires_query() -> None:
    spec = tools_mod.MCP_TOOLS["search_iocs"]
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({})
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({"query": ""})


async def test_search_iocs_rejects_bad_limit() -> None:
    spec = tools_mod.MCP_TOOLS["search_iocs"]
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({"query": "x", "limit": 0})
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({"query": "x", "limit": 5000})


# run_retro_hunt


async def test_run_retro_hunt_enqueues_job(
    store_with_data: store_mod.IOCStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(store_mod, "get_default_store", lambda: store_with_data)
    ioc = store_with_data.get(type_="ipv4", value="1.2.3.4")
    assert ioc is not None
    ioc_id = ioc.id
    spec = tools_mod.MCP_TOOLS["run_retro_hunt"]
    result = await spec.handler({"ioc_id": ioc_id, "platform": "chronicle"})
    assert result["status"] == "queued"
    assert result["platform"] == "chronicle"
    assert result["ioc_value"] == "1.2.3.4"
    assert isinstance(result["job_id"], int)


async def test_run_retro_hunt_unknown_ioc(
    store_with_data: store_mod.IOCStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(store_mod, "get_default_store", lambda: store_with_data)
    spec = tools_mod.MCP_TOOLS["run_retro_hunt"]
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({"ioc_id": 99999, "platform": "chronicle"})


async def test_run_retro_hunt_rejects_bad_platform(
    store_with_data: store_mod.IOCStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(store_mod, "get_default_store", lambda: store_with_data)
    spec = tools_mod.MCP_TOOLS["run_retro_hunt"]
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({"ioc_id": 1, "platform": "splunk"})


async def test_run_retro_hunt_requires_positive_id() -> None:
    spec = tools_mod.MCP_TOOLS["run_retro_hunt"]
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({"ioc_id": 0})
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({"ioc_id": -5})
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({"ioc_id": "abc"})  # type: ignore[arg-type]


# summarize_alert


async def test_summarize_alert_finds_by_dedupe_key(
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mock ``alerts.ingest.ingest_all`` so this test stays independent of
    the V1/Chronicle/DS wiring (which has its own end-to-end coverage)."""
    from datetime import UTC, datetime

    from secops_term.alerts import ingest as alerts_ingest
    from secops_term.alerts.types import Alert

    fake_alert = Alert(
        id="v1-99",
        source="vision_one",
        severity="high",
        title="Suspicious Login",
        detected_at=datetime(2026, 6, 1, 8, 0, 0, tzinfo=UTC),
        entities=(),
        raw={"id": "v1-99"},
        dedupe_key="vision_one:v1-99",
    )
    fake_result = alerts_ingest.IngestResult(
        per_source=[],
        alerts=[fake_alert],
        groups=[],
    )

    async def _fake_ingest(**_kwargs: object) -> alerts_ingest.IngestResult:
        return fake_result

    monkeypatch.setattr(alerts_ingest, "ingest_all", _fake_ingest)

    spec = tools_mod.MCP_TOOLS["summarize_alert"]
    result = await spec.handler({"dedupe_key": "vision_one:v1-99"})
    assert result["source"] == "vision_one"
    assert result["title"] == "Suspicious Login"


async def test_summarize_alert_unknown_key(tmp_root: Path) -> None:
    spec = tools_mod.MCP_TOOLS["summarize_alert"]
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({"dedupe_key": "chronicle:does-not-exist"})


async def test_summarize_alert_requires_key() -> None:
    spec = tools_mod.MCP_TOOLS["summarize_alert"]
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({})


# nl_to_udm / nl_to_v1


async def test_nl_to_udm_returns_prompt() -> None:
    spec = tools_mod.MCP_TOOLS["nl_to_udm"]
    result = await spec.handler({"question": "all DNS to evil.com"})
    assert result["target"] == "udm"
    assert "UDM Search" in result["system_prompt"]
    assert "all DNS to evil.com" in result["user_prompt"]
    assert "DO NOT execute" in result["guardrail"]


async def test_nl_to_v1_returns_prompt() -> None:
    spec = tools_mod.MCP_TOOLS["nl_to_v1"]
    result = await spec.handler({"question": "processes by alice"})
    assert result["target"] == "tmv1"
    assert "TMV1" in result["system_prompt"] or "Vision One" in result["system_prompt"]
    assert "processes by alice" in result["user_prompt"]


async def test_nl_to_udm_requires_question() -> None:
    spec = tools_mod.MCP_TOOLS["nl_to_udm"]
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({})
    with pytest.raises(tools_mod.ToolError):
        await spec.handler({"question": ""})


# Registry sanity


def test_registry_has_all_brief_tools() -> None:
    expected = {
        "search_iocs",
        "run_retro_hunt",
        "summarize_alert",
        "nl_to_udm",
        "nl_to_v1",
    }
    assert set(tools_mod.MCP_TOOLS) == expected


def test_registry_specs_have_schemas() -> None:
    for name, spec in tools_mod.MCP_TOOLS.items():
        assert spec.name == name
        assert spec.description
        assert spec.input_schema["type"] == "object"
