"""Prompt templates for NLP → query generation.

Per brief v3 §6.5: two flavors, NLP → UDM (Chronicle) and NLP → TMV1
(Vision One). The prompt for each ships with:

- A short cheat sheet of fields, operators, and common pitfalls.
- 5-10 few-shot examples (currently ``TODO`` placeholders — Phase 4 of
  the build is supposed to request these from the user, drawing from
  their existing UDM-Search reference doc).
- A strict output contract telling Claude to return ONLY the query, no
  prose, no fences, no explanation.

The few-shot blocks are kept in module-level constants so swapping in
the real examples is a one-spot edit when the user provides them.
"""

from __future__ import annotations

from typing import Final, Literal

QueryTarget = Literal["udm", "tmv1"]


# ---------- Chronicle UDM Search ----------

UDM_CHEAT_SHEET: Final[str] = """\
Chronicle UDM Search query reference:

- UDM Search uses a flat field=VALUE syntax. NOT the "rule { ... }" wrapper
  used by YARA-L detection rules. Returning a "rule {}" block is wrong.
- Common fields:
    metadata.event_type           e.g. NETWORK_DNS, PROCESS_LAUNCH, USER_LOGIN
    principal.hostname            source host
    principal.user.userid         source user
    principal.ip                  source IP
    target.hostname / target.ip   destination host / IP
    target.url                    destination URL
    network.dns.questions.name    DNS query name
    metadata.product_name         e.g. "Microsoft Defender for Endpoint"
    security_result.action        ALLOW | BLOCK | QUARANTINE
- Operators: =, !=, AND, OR, NOT. Use NOT (uppercase). Quote string values.
- Time is set in the UI / API params, NOT in the query string.
- Wildcards: re.matches(field, /pattern/) for regex; otherwise literal match.
- Pitfalls:
    * Don't wrap in "rule { ... }".
    * Don't include "events:" or "match:" — those are detection-rule syntax.
    * Strings must be double-quoted: principal.hostname = "WIN-01" not WIN-01.
    * Field names are dotted; never spaces.
"""

# TODO(user): Replace these placeholders with 5-10 real UDM Search
# examples from the user's UDM Search reference doc (the
# 14-investigation-categories document mentioned in the brief). Until
# then, these illustrate the expected shape so the prompt isn't empty.
UDM_FEW_SHOTS: Final[list[tuple[str, str]]] = [
    (
        "TODO(example 1): all DNS queries to example.com",
        'metadata.event_type = "NETWORK_DNS" AND network.dns.questions.name = "example.com"',
    ),
    (
        "TODO(example 2): logins by user alice in last 24h",
        'metadata.event_type = "USER_LOGIN" AND principal.user.userid = "alice"',
    ),
    (
        "TODO(example 3): processes launched on host WIN-01",
        'metadata.event_type = "PROCESS_LAUNCH" AND principal.hostname = "WIN-01"',
    ),
]

UDM_SYSTEM_PROMPT: Final[str] = (
    "You are a Chronicle UDM Search query generator. Your ONLY task is to\n"
    "translate a natural-language SOC question into a single UDM Search\n"
    "query. Do not explain. Do not wrap in code fences. Do not return YARA-L\n"
    "rule syntax. Return ONLY the query string."
)


# ---------- Vision One TMV1 Search ----------

TMV1_CHEAT_SHEET: Final[str] = """\
Trend Micro Vision One Search (TMV1) query reference:

- TMV1 query syntax: field:"value" with AND, OR, NOT (uppercase boolean).
- Common fields:
    eventName            e.g. PROCESS_CREATE, NETWORK_CONNECT
    hostName             endpoint hostname
    userName             user account
    src                  source IP
    dst                  destination IP
    ipAddress            generic IP (matches src OR dst in some indexes)
    dstHost              destination host / domain
    processName / objectFilePath
    objectFileHashSha256
    detectionType        e.g. malware, suspicious-behavior
- Time range goes in the API request body / query params, NOT in the query.
- Wildcards: * within quotes works for prefix/contains in some fields.
- Pitfalls:
    * Don't include time ranges in the query string.
    * String values must be double-quoted.
    * Boolean operators must be UPPERCASE (AND, not "and").
    * Don't return JSON — just the query string the V1 console accepts.
"""

# TODO(user): Replace with 5-10 real TMV1 Search examples from production
# investigations.
TMV1_FEW_SHOTS: Final[list[tuple[str, str]]] = [
    (
        "TODO(example 1): connections to suspicious IP 1.2.3.4",
        'dst:"1.2.3.4" OR src:"1.2.3.4" OR ipAddress:"1.2.3.4"',
    ),
    (
        "TODO(example 2): processes launched by user alice",
        'eventName:"PROCESS_CREATE" AND userName:"alice"',
    ),
    (
        "TODO(example 3): file hash detected anywhere",
        'objectFileHashSha256:"abc123def456"',
    ),
]

TMV1_SYSTEM_PROMPT: Final[str] = (
    "You are a Trend Micro Vision One Search (TMV1) query generator. Your\n"
    "ONLY task is to translate a natural-language SOC question into a single\n"
    "TMV1 query. Do not explain. Do not wrap in code fences. Do not include\n"
    "time ranges in the query. Return ONLY the query string."
)


# ---------- Public API ----------


def render_prompt(target: QueryTarget, question: str) -> tuple[str, str]:
    """Return ``(system_prompt, user_prompt)`` for the given target.

    The system prompt locks the output contract; the user prompt
    embeds the cheat sheet, few-shot examples, and the user's question.

    The bridge layer is responsible for sentinel-fencing if any
    *external* untrusted content (e.g. an alert description) is added
    later. The user's typed question itself is treated as trusted —
    the user is the operator.
    """
    if target == "udm":
        cheat = UDM_CHEAT_SHEET
        examples = UDM_FEW_SHOTS
        system = UDM_SYSTEM_PROMPT
    elif target == "tmv1":
        cheat = TMV1_CHEAT_SHEET
        examples = TMV1_FEW_SHOTS
        system = TMV1_SYSTEM_PROMPT
    else:  # pragma: no cover - exhaustive Literal
        raise ValueError(f"unknown target: {target!r}")

    parts: list[str] = []
    parts.append(cheat)
    parts.append("Examples (intent → query):")
    for intent, query in examples:
        parts.append(f"- {intent}\n  {query}")
    parts.append("Now translate this question to a single query:")
    parts.append(question.strip())
    parts.append("Output the query and ONLY the query. No prose, no fences.")
    return system, "\n\n".join(parts)


__all__ = [
    "TMV1_CHEAT_SHEET",
    "TMV1_FEW_SHOTS",
    "TMV1_SYSTEM_PROMPT",
    "UDM_CHEAT_SHEET",
    "UDM_FEW_SHOTS",
    "UDM_SYSTEM_PROMPT",
    "QueryTarget",
    "render_prompt",
]
