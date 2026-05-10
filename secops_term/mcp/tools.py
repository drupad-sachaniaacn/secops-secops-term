"""MCP tool implementations — pure-Python async functions.

Each tool takes a ``dict`` of arguments (matching its declared schema)
and returns a ``dict`` of results, both already JSON-serialisable.
The wire-protocol wrapper in :mod:`secops_term.mcp.server` adapts
these into MCP ``tool/call`` responses; tests exercise them directly.

Per brief §7.2 the exposed surface is::

    search_iocs        — IOC store query (read-only)
    run_retro_hunt     — enqueue a retro-hunt job (write to local DB)
    summarize_alert    — fetch one alert by id from a fresh ingest
    nl_to_udm          — NLP → Chronicle UDM Search (review-then-execute)
    nl_to_v1           — NLP → Vision One TMV1 Search (review-then-execute)

The MCP server NEVER executes the AI-generated query; it returns it for
the operator to confirm in their Claude Code chat.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any


class ToolError(Exception):
    """Tool implementation rejected the call (bad args / underlying failure)."""


ToolHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class ToolSpec:
    """Declared interface of a single MCP tool.

    ``input_schema`` is a JSON-Schema dict (drafts 7+) describing the
    accepted ``arguments`` payload. The MCP wire protocol serialises
    this directly into ``tools/list`` responses.
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler


# --- search_iocs ---


async def _search_iocs(args: dict[str, Any]) -> dict[str, Any]:
    """Search the local IOC store by free-text query."""
    query = args.get("query")
    limit = int(args.get("limit", 50))
    if not isinstance(query, str) or not query.strip():
        raise ToolError("`query` is required and must be a non-empty string")
    if limit <= 0 or limit > 1000:
        raise ToolError("`limit` must be in 1..1000")

    # Lazy import — keeps the module import cheap so the registry can
    # be loaded without spinning up the IOC store / DB.
    from secops_term.intel import store as store_mod

    iocs = store_mod.get_default_store().search(query, limit=limit)
    return {
        "matches": [
            {
                "id": ioc.id,
                "type": ioc.type,
                "value": ioc.value,
                "confidence": ioc.confidence,
                "tags": list(ioc.tags),
                "first_seen": ioc.first_seen.isoformat(),
                "last_seen": ioc.last_seen.isoformat(),
            }
            for ioc in iocs
        ],
        "count": len(iocs),
    }


# --- run_retro_hunt ---


async def _run_retro_hunt(args: dict[str, Any]) -> dict[str, Any]:
    """Enqueue a retro-hunt job for an IOC."""
    ioc_id_raw = args.get("ioc_id")
    platform = args.get("platform", "chronicle")
    if not isinstance(ioc_id_raw, int) or ioc_id_raw <= 0:
        raise ToolError("`ioc_id` is required and must be a positive integer")
    if platform not in ("chronicle", "vision_one"):
        raise ToolError("`platform` must be 'chronicle' or 'vision_one'")

    from secops_term.intel import store as store_mod

    store = store_mod.get_default_store()
    ioc = store.get_by_id(ioc_id_raw)
    if ioc is None:
        raise ToolError(f"no IOC with id={ioc_id_raw}")
    job_id = store.enqueue_retro_hunt(ioc_id_raw, platform)
    return {
        "job_id": job_id,
        "ioc_id": ioc_id_raw,
        "ioc_type": ioc.type,
        "ioc_value": ioc.value,
        "platform": platform,
        "status": "queued",
    }


# --- summarize_alert ---


async def _summarize_alert(args: dict[str, Any]) -> dict[str, Any]:
    """Return the structured form of one alert (by dedupe_key) from a fresh ingest.

    The MCP server does NOT call the AI bridge here — Claude is on the
    other side of the wire and should do its own summarising. We just
    surface the alert fields.
    """
    dedupe_key = args.get("dedupe_key")
    if not isinstance(dedupe_key, str) or not dedupe_key.strip():
        raise ToolError("`dedupe_key` is required (e.g. 'chronicle:abc-123')")

    from secops_term.alerts import ingest as alerts_ingest

    result = await alerts_ingest.ingest_all()
    for alert in result.alerts:
        if alert.dedupe_key == dedupe_key:
            return {
                "id": alert.id,
                "source": alert.source,
                "severity": alert.severity,
                "title": alert.title,
                "detected_at": alert.detected_at.isoformat(),
                "dedupe_key": alert.dedupe_key,
                "entities": [{"type": e.type, "value": e.value} for e in alert.entities],
                "raw": alert.raw,
            }
    raise ToolError(f"no alert with dedupe_key={dedupe_key!r}")


# --- nl_to_udm / nl_to_v1 ---


async def _nl_to_query(target: str, args: dict[str, Any]) -> dict[str, Any]:
    question = args.get("question")
    if not isinstance(question, str) or not question.strip():
        raise ToolError("`question` is required (natural-language SOC question)")
    # Important: this tool does NOT execute the resulting query. It
    # generates and validates only. The Claude side is expected to
    # show the result to the operator who then runs it in Chronicle /
    # V1 themselves. (Brief §6.5: never auto-execute.)
    from secops_term.ai.nlp_prompts import render_prompt

    system, user = render_prompt(target, question)  # type: ignore[arg-type]
    return {
        "target": target,
        "question": question,
        "system_prompt": system,
        "user_prompt": user,
        "validator_hint": (
            "After Claude returns a query, run it through "
            "`secops_term.ai.nlp_validators.validate_query` for a structural "
            "self-check before pushing to the platform."
        ),
        # Repeat the never-auto-execute guardrail in the response so a
        # Claude prompt that ignores the system prompt still sees it.
        "guardrail": (
            "DO NOT execute this query automatically. Show it to the operator "
            "and wait for explicit confirmation before pushing to "
            f"{('Chronicle' if target == 'udm' else 'Vision One')}."
        ),
        # Pointer to the validator module so a Claude client can call
        # back through another tool round-trip if it wants a self-check.
        "validator_module": "secops_term.ai.nlp_validators",
    }


async def _nl_to_udm(args: dict[str, Any]) -> dict[str, Any]:
    return await _nl_to_query("udm", args)


async def _nl_to_v1(args: dict[str, Any]) -> dict[str, Any]:
    return await _nl_to_query("tmv1", args)


# --- registry ---


MCP_TOOLS: dict[str, ToolSpec] = {
    "search_iocs": ToolSpec(
        name="search_iocs",
        description=(
            "Search the local SecOps Terminal IOC store by free-text query. "
            "Read-only; returns up to ``limit`` matches."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Free-text query."},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "default": 50,
                },
            },
            "required": ["query"],
        },
        handler=_search_iocs,
    ),
    "run_retro_hunt": ToolSpec(
        name="run_retro_hunt",
        description=(
            "Enqueue a retro-hunt job for an IOC on the chosen platform. "
            "The job runs asynchronously; this returns immediately with "
            "``job_id`` so the caller can poll status later."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "ioc_id": {"type": "integer", "minimum": 1},
                "platform": {
                    "type": "string",
                    "enum": ["chronicle", "vision_one"],
                    "default": "chronicle",
                },
            },
            "required": ["ioc_id"],
        },
        handler=_run_retro_hunt,
    ),
    "summarize_alert": ToolSpec(
        name="summarize_alert",
        description=(
            "Fetch one alert (by ``dedupe_key``) from a fresh cross-source "
            "ingest. Returns the structured fields; the LLM client is "
            "expected to do its own summarising."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "dedupe_key": {
                    "type": "string",
                    "description": "Format: '<source>:<id>'.",
                }
            },
            "required": ["dedupe_key"],
        },
        handler=_summarize_alert,
    ),
    "nl_to_udm": ToolSpec(
        name="nl_to_udm",
        description=(
            "Render the prompt + cheat sheet + few-shots for translating a "
            "natural-language question into a Chronicle UDM Search query. "
            "Returns the prompt; the LLM produces the query, the operator "
            "runs it manually (NEVER auto-executed)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "question": {"type": "string"},
            },
            "required": ["question"],
        },
        handler=_nl_to_udm,
    ),
    "nl_to_v1": ToolSpec(
        name="nl_to_v1",
        description=("Same as ``nl_to_udm`` but for Trend Micro Vision One (TMV1) Search."),
        input_schema={
            "type": "object",
            "properties": {
                "question": {"type": "string"},
            },
            "required": ["question"],
        },
        handler=_nl_to_v1,
    ),
}


__all__ = ["MCP_TOOLS", "ToolError", "ToolHandler", "ToolSpec"]
