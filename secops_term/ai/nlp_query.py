"""High-level NLP → query helper — orchestrates prompt + bridge + validation.

Per brief v3 §6.5: ``generate_query`` calls the AI bridge with the
target-specific system prompt and few-shot examples, strips Claude's
inevitable Markdown / extra prose, runs the regex-level validator,
and returns the result. **Never auto-executes** — callers must show
the query to the user, get explicit confirmation, and only then push
to Chronicle / Vision One.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from secops_term.ai.bridge import AIBridge
from secops_term.ai.nlp_prompts import QueryTarget, render_prompt
from secops_term.ai.nlp_validators import ValidationResult, validate_query

# Markdown code fence at start/end (``` or ```language) — Claude often
# returns one even when told not to.
_FENCE_OPEN = re.compile(r"^\s*```(?:\w+)?\s*\n", re.M)
_FENCE_CLOSE = re.compile(r"\n\s*```\s*$", re.M)


@dataclass(frozen=True)
class GeneratedQuery:
    """Result of an NLP → query run."""

    target: QueryTarget
    question: str
    raw_response: str
    query: str
    validation: ValidationResult


async def generate_query(
    bridge: AIBridge,
    *,
    target: QueryTarget,
    question: str,
) -> GeneratedQuery:
    """Translate ``question`` into a ``target`` query via the bridge.

    The bridge's ``complete()`` is called with the target-specific
    system prompt and user prompt. The response is cleaned of any
    code-fence wrapping and validated. The user is responsible for
    reviewing the query before executing it.
    """
    system, user_prompt = render_prompt(target, question)
    raw = await bridge.complete(user_prompt, system=system)
    query = _clean_response(raw)
    validation = validate_query(target, query)
    return GeneratedQuery(
        target=target,
        question=question,
        raw_response=raw,
        query=query,
        validation=validation,
    )


def _clean_response(text: str) -> str:
    """Strip code fences and surrounding whitespace from Claude's output.

    Claude tends to wrap output in ```...``` even when instructed not
    to. We tolerate that one pattern and refuse to do anything cleverer
    — over-cleaning risks corrupting an otherwise-valid query.
    """
    cleaned = text.strip()
    cleaned = _FENCE_OPEN.sub("", cleaned, count=1)
    cleaned = _FENCE_CLOSE.sub("", cleaned, count=1)
    return cleaned.strip()


__all__ = ["GeneratedQuery", "generate_query"]
