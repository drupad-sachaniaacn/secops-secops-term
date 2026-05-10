"""Regex-level validators for AI-generated UDM / TMV1 queries."""

from __future__ import annotations

from secops_term.ai import nlp_validators

# Empty / whitespace


def test_empty_query_invalid() -> None:
    r = nlp_validators.validate_query("udm", "")
    assert not r.ok
    assert "empty" in r.errors[0]


def test_whitespace_only_query_invalid() -> None:
    r = nlp_validators.validate_query("udm", "   \n\t  ")
    assert not r.ok


# Balanced quotes / parens (target-agnostic)


def test_unbalanced_quotes_invalid_for_udm() -> None:
    r = nlp_validators.validate_query("udm", 'principal.hostname = "WIN-01')
    assert not r.ok
    assert any("quotes" in e for e in r.errors)


def test_unbalanced_parens_invalid_for_tmv1() -> None:
    r = nlp_validators.validate_query("tmv1", '(eventName:"PROCESS_CREATE"')
    assert not r.ok
    assert any("parentheses" in e for e in r.errors)


def test_escaped_quotes_count_correctly() -> None:
    # Two unescaped quotes; backslash-escapes shouldn't trip the counter.
    q = 'metadata.event_type = "FOO\\"BAR"'
    r = nlp_validators.validate_query("udm", q)
    assert all("quotes" not in e for e in r.errors)


# UDM-specific


def test_udm_rejects_yaral_rule_wrapper() -> None:
    q = 'rule my_rule { events: $e.metadata.event_type = "x" }'
    r = nlp_validators.validate_query("udm", q)
    assert not r.ok
    assert any("YARA-L" in e or "rule" in e for e in r.errors)


def test_udm_rejects_yaral_block_keywords() -> None:
    q = 'metadata.event_type = "X"\nevents:\n  $e'
    r = nlp_validators.validate_query("udm", q)
    assert not r.ok


def test_udm_warns_on_unknown_field_prefix() -> None:
    q = 'totallymadeupfield.thing = "x"'
    r = nlp_validators.validate_query("udm", q)
    # No errors — just a warning so the user can decide.
    assert r.ok
    assert any("unrecognised UDM field prefix" in w for w in r.warnings)


def test_udm_known_prefix_no_warning() -> None:
    q = 'metadata.event_type = "NETWORK_DNS" AND principal.hostname = "x"'
    r = nlp_validators.validate_query("udm", q)
    assert r.ok
    assert not r.warnings


# TMV1-specific


def test_tmv1_warns_on_unknown_field() -> None:
    q = 'totallyMadeUp:"x"'
    r = nlp_validators.validate_query("tmv1", q)
    assert r.ok
    assert any("unrecognised TMV1 field" in w for w in r.warnings)


def test_tmv1_known_fields_no_warning() -> None:
    q = 'eventName:"PROCESS_CREATE" AND userName:"alice"'
    r = nlp_validators.validate_query("tmv1", q)
    assert r.ok
    assert not r.warnings


def test_tmv1_boolean_keywords_not_flagged_as_fields() -> None:
    q = 'eventName:"X" AND userName:"y" OR src:"1.1.1.1" NOT dst:"2.2.2.2"'
    r = nlp_validators.validate_query("tmv1", q)
    assert r.ok
    assert not r.warnings


# ValidationResult shape


def test_validation_result_ok_property() -> None:
    ok = nlp_validators.ValidationResult(target="udm", query="x", errors=())
    assert ok.ok is True
    not_ok = nlp_validators.ValidationResult(target="udm", query="x", errors=("e",))
    assert not_ok.ok is False
