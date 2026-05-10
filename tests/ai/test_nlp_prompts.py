"""Prompt rendering for NLP → UDM / TMV1 translation."""

from __future__ import annotations

import pytest

from secops_term.ai import nlp_prompts

# UDM


def test_udm_render_includes_cheat_sheet_and_examples() -> None:
    system, user = nlp_prompts.render_prompt("udm", "find DNS to evil.com")
    assert "UDM Search" in system
    assert "metadata.event_type" in user
    assert "rule {" not in system  # don't accidentally suggest YARA-L
    # At least one of the few-shot examples must be present.
    assert any(intent in user for intent, _ in nlp_prompts.UDM_FEW_SHOTS)
    assert "find DNS to evil.com" in user


def test_udm_render_includes_output_contract() -> None:
    system, user = nlp_prompts.render_prompt("udm", "q")
    # System prompt must lock the output: no fences, no prose.
    assert "ONLY" in system
    assert "YARA-L" in system or "rule" in system
    assert "fences" in user or "fences" in system or "fence" in user


def test_udm_render_strips_question_whitespace() -> None:
    _, user = nlp_prompts.render_prompt("udm", "  find logs  \n")
    assert "find logs" in user
    # Trailing newline / spaces removed.
    assert "find logs  \n" not in user


# TMV1


def test_tmv1_render_includes_cheat_sheet() -> None:
    system, user = nlp_prompts.render_prompt("tmv1", "show processes by alice")
    assert "TMV1" in system or "Vision One" in system
    assert "eventName" in user
    assert "show processes by alice" in user


def test_tmv1_render_includes_examples() -> None:
    _, user = nlp_prompts.render_prompt("tmv1", "q")
    assert any(intent in user for intent, _ in nlp_prompts.TMV1_FEW_SHOTS)


# Unknown target


def test_render_unknown_target_raises() -> None:
    with pytest.raises(ValueError):
        nlp_prompts.render_prompt("oracle", "q")  # type: ignore[arg-type]
