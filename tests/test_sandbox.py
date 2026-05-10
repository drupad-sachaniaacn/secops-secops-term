"""Sandbox: legitimate-use evaluation (tests/security/ has the injection corpus)."""

from __future__ import annotations

import pytest

from secops_term.playbooks import sandbox

# Constants


def test_constant_int() -> None:
    assert sandbox.evaluate("42", {}) == 42


def test_constant_string() -> None:
    assert sandbox.evaluate("'hello'", {}) == "hello"


def test_constant_float() -> None:
    assert sandbox.evaluate("3.14", {}) == 3.14


def test_constant_bool() -> None:
    assert sandbox.evaluate("True", {}) is True
    assert sandbox.evaluate("False", {}) is False


def test_constant_none() -> None:
    assert sandbox.evaluate("None", {}) is None


# Arithmetic


def test_arithmetic_precedence() -> None:
    assert sandbox.evaluate("1 + 2 * 3", {}) == 7


def test_subtraction() -> None:
    assert sandbox.evaluate("10 - 4", {}) == 6


def test_division() -> None:
    assert sandbox.evaluate("10 / 4", {}) == 2.5


def test_modulo() -> None:
    assert sandbox.evaluate("10 % 3", {}) == 1


def test_negation() -> None:
    assert sandbox.evaluate("-5", {}) == -5


def test_not() -> None:
    assert sandbox.evaluate("not True", {}) is False
    assert sandbox.evaluate("not False", {}) is True


# Comparisons


def test_comparisons() -> None:
    assert sandbox.evaluate("1 < 2", {}) is True
    assert sandbox.evaluate("2 == 2", {}) is True
    assert sandbox.evaluate("3 != 2", {}) is True


def test_chained_comparisons() -> None:
    assert sandbox.evaluate("3 > 2 > 1", {}) is True
    assert sandbox.evaluate("1 < 2 < 1", {}) is False


# Bool ops


def test_and() -> None:
    assert sandbox.evaluate("True and False", {}) is False
    assert sandbox.evaluate("True and True", {}) is True


def test_or() -> None:
    assert sandbox.evaluate("True or False", {}) is True
    assert sandbox.evaluate("False or False", {}) is False


# Membership


def test_in_list() -> None:
    assert sandbox.evaluate("'sha256' in ['sha256', 'sha1']", {}) is True
    assert sandbox.evaluate("'unknown' in ['sha256', 'sha1']", {}) is False


def test_not_in_list() -> None:
    assert sandbox.evaluate("1 not in [2, 3]", {}) is True


# Conditional expression


def test_ifexp() -> None:
    assert sandbox.evaluate("'a' if True else 'b'", {}) == "a"
    assert sandbox.evaluate("'a' if False else 'b'", {}) == "b"


# Name / context


def test_name_lookup() -> None:
    assert sandbox.evaluate("ioc", {"ioc": {"value": "x"}}) == {"value": "x"}


def test_attribute_access() -> None:
    ctx = {"ioc": {"type": "sha256", "value": "abc"}}
    assert sandbox.evaluate("ioc.type", ctx) == "sha256"
    assert sandbox.evaluate("ioc.value", ctx) == "abc"


def test_chained_attribute_access() -> None:
    ctx = {"steps": {"retro_chr": {"hits": 5}, "retro_v1": {"hits": 3}}}
    assert sandbox.evaluate("steps.retro_chr.hits", ctx) == 5
    assert sandbox.evaluate("steps.retro_v1.hits", ctx) == 3


def test_subscript_with_string_key() -> None:
    # Hyphens in step IDs require subscript (not valid attribute names).
    ctx = {"steps": {"retro-chr": {"hits": 5}}}
    assert sandbox.evaluate("steps['retro-chr']['hits']", ctx) == 5


def test_attribute_not_found() -> None:
    with pytest.raises(sandbox.NotFound):
        sandbox.evaluate("ioc.missing", {"ioc": {"value": "x"}})


def test_subscript_not_found() -> None:
    with pytest.raises(sandbox.NotFound):
        sandbox.evaluate("ioc['missing']", {"ioc": {"value": "x"}})


def test_name_not_in_context() -> None:
    # ``ioc`` is in the WHITELIST, but missing from this particular context.
    with pytest.raises(sandbox.NotFound):
        sandbox.evaluate("ioc.value", {})


def test_attribute_access_on_non_mapping() -> None:
    # Once a value resolves to a string, you can't keep accessing attributes.
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate("ioc.value.upper_case", {"ioc": {"value": "x"}})


# Real-world playbook expressions


def test_playbook_when_ioc_type_in_list() -> None:
    ctx = {"ioc": {"type": "sha256", "value": "abc"}}
    assert sandbox.evaluate("ioc.type in ['sha256', 'sha1', 'md5']", ctx) is True


def test_playbook_when_steps_have_hits() -> None:
    ctx = {"steps": {"a": {"hits": 5}, "b": {"hits": 0}}}
    assert sandbox.evaluate("steps.a.hits > 0 or steps.b.hits > 0", ctx) is True


def test_playbook_when_no_hits() -> None:
    ctx = {"steps": {"a": {"hits": 0}, "b": {"hits": 0}}}
    assert sandbox.evaluate("steps.a.hits > 0 or steps.b.hits > 0", ctx) is False


# Templates


def test_template_single_substitution() -> None:
    out = sandbox.evaluate_template(
        "Found IOC: {{ ioc.value }}",
        {"ioc": {"value": "abc"}},
    )
    assert out == "Found IOC: abc"


def test_template_multiple_substitutions() -> None:
    out = sandbox.evaluate_template(
        "{{ steps.a.hits }} CHR / {{ steps.b.hits }} V1",
        {"steps": {"a": {"hits": 5}, "b": {"hits": 3}}},
    )
    assert out == "5 CHR / 3 V1"


def test_template_no_substitutions() -> None:
    assert sandbox.evaluate_template("plain text", {}) == "plain text"


def test_template_with_whitespace_in_braces() -> None:
    out = sandbox.evaluate_template(
        "{{   ioc.value   }}",
        {"ioc": {"value": "xyz"}},
    )
    assert out == "xyz"


def test_template_arithmetic() -> None:
    assert sandbox.evaluate_template("{{ 1 + 2 }}", {}) == "3"


def test_template_failing_expr_propagates() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.evaluate_template("{{ ioc.__class__ }}", {"ioc": {}})


def test_template_real_world_message() -> None:
    ctx = {
        "ioc": {"value": "abc123"},
        "steps": {"retro_chr": {"hits": 5}, "retro_v1": {"hits": 3}},
    }
    out = sandbox.evaluate_template(
        "Retro hunt hit for {{ ioc.value }} - "
        "{{ steps.retro_chr.hits }} CHR / {{ steps.retro_v1.hits }} V1",
        ctx,
    )
    assert out == "Retro hunt hit for abc123 - 5 CHR / 3 V1"
