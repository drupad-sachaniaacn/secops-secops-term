"""generate_query — orchestrates prompt + bridge + validator."""

from __future__ import annotations

from secops_term.ai import nlp_query


class _FakeBridge:
    def __init__(self, response: str) -> None:
        self.response = response
        self.last_prompt: str | None = None
        self.last_system: str | None = None

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        untrusted_inputs: list[str] | None = None,
    ) -> str:
        self.last_prompt = prompt
        self.last_system = system
        return self.response

    async def health_check(self) -> bool:  # pragma: no cover - unused
        return True


# Happy path


async def test_generate_returns_clean_query() -> None:
    bridge = _FakeBridge('metadata.event_type = "NETWORK_DNS"')
    result = await nlp_query.generate_query(bridge, target="udm", question="all DNS events")
    assert result.query == 'metadata.event_type = "NETWORK_DNS"'
    assert result.validation.ok
    assert result.target == "udm"
    assert result.question == "all DNS events"


async def test_generate_strips_markdown_fences() -> None:
    bridge = _FakeBridge('```\nmetadata.event_type = "X"\n```')
    result = await nlp_query.generate_query(bridge, target="udm", question="q")
    assert result.query == 'metadata.event_type = "X"'
    # Raw response preserved for debugging.
    assert "```" in result.raw_response


async def test_generate_strips_language_fences() -> None:
    bridge = _FakeBridge('```udm\nprincipal.hostname = "X"\n```')
    result = await nlp_query.generate_query(bridge, target="udm", question="q")
    assert result.query == 'principal.hostname = "X"'


async def test_generate_passes_question_to_bridge() -> None:
    bridge = _FakeBridge('eventName:"X"')
    await nlp_query.generate_query(bridge, target="tmv1", question="show all process creates")
    assert bridge.last_prompt is not None
    assert "show all process creates" in bridge.last_prompt
    assert bridge.last_system is not None
    assert "TMV1" in bridge.last_system or "Vision One" in bridge.last_system


# Validation flows through


async def test_generate_validation_catches_yaral_wrapper() -> None:
    bridge = _FakeBridge("rule my_rule { events: $x }")
    result = await nlp_query.generate_query(bridge, target="udm", question="q")
    assert not result.validation.ok
    assert any("YARA-L" in e or "rule" in e for e in result.validation.errors)


async def test_generate_validation_warnings_surface() -> None:
    bridge = _FakeBridge('madeUpField:"x"')
    result = await nlp_query.generate_query(bridge, target="tmv1", question="q")
    assert result.validation.ok  # warnings, not errors
    assert any("unrecognised TMV1 field" in w for w in result.validation.warnings)


async def test_generate_validation_invalid_on_unbalanced_quotes() -> None:
    bridge = _FakeBridge('metadata.event_type = "broken')
    result = await nlp_query.generate_query(bridge, target="udm", question="q")
    assert not result.validation.ok


# TMV1 target


async def test_generate_tmv1_target() -> None:
    bridge = _FakeBridge('dst:"1.2.3.4"')
    result = await nlp_query.generate_query(
        bridge, target="tmv1", question="connections to 1.2.3.4"
    )
    assert result.target == "tmv1"
    assert result.query == 'dst:"1.2.3.4"'
    assert result.validation.ok
