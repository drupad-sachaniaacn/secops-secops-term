"""Tainted-string registry redacts every occurrence and never leaks contents."""

from __future__ import annotations

import pytest

from secops_term.core.redact import SecretRegistry

pytestmark = pytest.mark.security


def test_redact_replaces_value() -> None:
    reg = SecretRegistry()
    reg.taint("sk-supersecret-12345", "vt:default:api_key")
    out = reg.redact("API key is sk-supersecret-12345 — handle with care")
    assert "sk-supersecret" not in out
    assert "<redacted:vt:default:api_key>" in out


def test_redact_handles_multiple_occurrences() -> None:
    reg = SecretRegistry()
    reg.taint("topsecretvalue", "x")
    out = reg.redact("topsecretvalue and again topsecretvalue")
    assert out.count("<redacted:x>") == 2
    assert "topsecretvalue" not in out


def test_redact_handles_overlapping_secrets() -> None:
    reg = SecretRegistry()
    reg.taint("longerSECRETvalue", "long")
    reg.taint("SECRETvalue", "short")
    out = reg.redact("payload longerSECRETvalue more SECRETvalue tail")
    assert "longerSECRETvalue" not in out
    assert "<redacted:long>" in out
    assert "<redacted:short>" in out


def test_redact_too_short_value_raises() -> None:
    reg = SecretRegistry()
    with pytest.raises(ValueError):
        reg.taint("ab", "tiny")


def test_redact_empty_value_ignored() -> None:
    reg = SecretRegistry()
    reg.taint("", "empty")  # silently ignored
    assert len(reg) == 0


def test_redact_empty_text_passthrough() -> None:
    reg = SecretRegistry()
    reg.taint("topsecretvalue", "x")
    assert reg.redact("") == ""


def test_redact_no_secrets_passthrough() -> None:
    reg = SecretRegistry()
    assert reg.redact("nothing to see here") == "nothing to see here"


def test_repr_does_not_leak_contents() -> None:
    reg = SecretRegistry()
    reg.taint("supersecretpayload", "x")
    r = repr(reg)
    assert "supersecret" not in r
    assert "1 entries" in r


def test_clear_removes_taints() -> None:
    reg = SecretRegistry()
    reg.taint("topsecretvalue", "x")
    reg.clear()
    assert reg.redact("topsecretvalue") == "topsecretvalue"


def test_taint_idempotent() -> None:
    reg = SecretRegistry()
    reg.taint("topsecretvalue", "x")
    reg.taint("topsecretvalue", "x")
    assert len(reg) == 1


def test_redact_with_regex_special_chars() -> None:
    reg = SecretRegistry()
    reg.taint("a.b.c.d.e", "dotted")
    out = reg.redact("value a.b.c.d.e here")
    assert "a.b.c.d.e" not in out
    assert "<redacted:dotted>" in out
