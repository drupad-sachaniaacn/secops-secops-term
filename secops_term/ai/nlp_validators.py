"""Regex-level self-check validators for AI-generated queries.

Per brief v3 §6.5: UDM/TMV1 queries returned by the AI bridge get a
cheap structural check before being shown to the user. The validator
NEVER auto-rejects — its purpose is to give the user a heads-up
("Claude returned a `rule {}` wrapper, which UDM Search doesn't
accept") so they can decide to regenerate or hand-edit.

Rules:

- **Balanced quotes.** Odd count of unescaped ``"`` → broken.
- **Balanced parens.** Mismatched ``(`` / ``)`` → broken.
- **Field prefixes are recognised.** Tokens that *look* like
  ``field=`` or ``field:`` should map to a known field family for the
  target. Unknown prefixes get warned, not rejected — the field list
  drifts, and we'd rather a false-positive than a false-negative.
- **UDM only: no ``rule { ... }`` wrapper.** That's YARA-L detection
  syntax, not Search syntax. Hard reject — this one's unambiguous.
- **UDM only: no ``events:`` / ``match:`` blocks** (also YARA-L).
- **Empty / whitespace-only.** Always invalid.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

from secops_term.ai.nlp_prompts import QueryTarget

# Recognised UDM field prefixes (top-of-dotted-path). Drifts, so
# unknown prefixes generate a warning rather than an error.
_UDM_FIELD_PREFIXES: Final[frozenset[str]] = frozenset(
    {
        "metadata",
        "principal",
        "target",
        "src",
        "dst",
        "network",
        "security_result",
        "about",
        "intermediary",
        "observer",
        "extracted",
        "additional",
    }
)

# Recognised TMV1 fields.
_TMV1_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "eventName",
        "hostName",
        "userName",
        "src",
        "dst",
        "ipAddress",
        "dstHost",
        "srcHost",
        "processName",
        "processCmd",
        "parentName",
        "objectName",
        "objectFilePath",
        "objectFileHashSha256",
        "objectFileHashSha1",
        "objectFileHashMd5",
        "objectIp",
        "objectUrl",
        "detectionType",
        "endpointHostName",
    }
)

# Captures `<field>=` (UDM) or `<field>:` (TMV1) at the start of a
# token. Field names are dotted-snake (UDM) or camelCase (TMV1).
_UDM_FIELD_TOKEN = re.compile(r"\b([a-z][a-z0-9_]*)(?:\.[a-z][a-z0-9_]*)*\s*[=!]+")
_TMV1_FIELD_TOKEN = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*)\s*:")
_RULE_WRAPPER = re.compile(r"\brule\s+\w*\s*\{")
_YARAL_BLOCKS = re.compile(r"\b(events|match|condition|outcome|meta)\s*:\s*$", re.M)


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of running a query through the regex-level validator."""

    target: QueryTarget
    query: str
    errors: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return not self.errors


def validate_query(target: QueryTarget, query: str) -> ValidationResult:
    """Run the structural checks for ``target`` against ``query``."""
    errors: list[str] = []
    warnings: list[str] = []

    stripped = query.strip()
    if not stripped:
        errors.append("query is empty")
        return ValidationResult(target=target, query=query, errors=tuple(errors))

    # 1. Balanced double quotes (count unescaped " — naive but matches
    #    the simple syntaxes both targets use).
    quote_count = _count_unescaped_quotes(stripped)
    if quote_count % 2 != 0:
        errors.append(f"unbalanced double quotes (found {quote_count})")

    # 2. Balanced parens.
    paren_balance = stripped.count("(") - stripped.count(")")
    if paren_balance != 0:
        errors.append(
            f"unbalanced parentheses (open={stripped.count('(')}, close={stripped.count(')')})"
        )

    if target == "udm":
        _check_udm(stripped, errors, warnings)
    elif target == "tmv1":
        _check_tmv1(stripped, errors, warnings)

    return ValidationResult(
        target=target,
        query=query,
        errors=tuple(errors),
        warnings=tuple(warnings),
    )


def _check_udm(query: str, errors: list[str], warnings: list[str]) -> None:
    if _RULE_WRAPPER.search(query):
        errors.append(
            "looks like YARA-L rule syntax (`rule { ... }`); "
            "UDM Search uses flat field=VALUE expressions"
        )
    if _YARAL_BLOCKS.search(query):
        errors.append(
            "contains YARA-L block keywords (events:/match:/condition:); "
            "those are detection-rule syntax, not UDM Search"
        )
    found_prefixes = {m.group(1).split(".")[0] for m in _UDM_FIELD_TOKEN.finditer(query)}
    unknown = sorted(found_prefixes - _UDM_FIELD_PREFIXES)
    if unknown:
        warnings.append(
            f"unrecognised UDM field prefix(es): {', '.join(unknown)} — "
            "may be a typo or a newer field; verify against Chronicle docs"
        )


def _check_tmv1(query: str, errors: list[str], warnings: list[str]) -> None:
    found_fields = {m.group(1) for m in _TMV1_FIELD_TOKEN.finditer(query)}
    # Discard tokens that are obviously inside a quoted value or an
    # operator alias by stripping known boolean keywords.
    found_fields.discard("AND")
    found_fields.discard("OR")
    found_fields.discard("NOT")
    unknown = sorted(found_fields - _TMV1_FIELDS)
    if unknown:
        warnings.append(
            f"unrecognised TMV1 field(s): {', '.join(unknown)} — "
            "may be a typo or a newer field; verify against V1 docs"
        )


def _count_unescaped_quotes(s: str) -> int:
    count = 0
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\":
            i += 2
            continue
        if ch == '"':
            count += 1
        i += 1
    return count


__all__ = ["ValidationResult", "validate_query"]
