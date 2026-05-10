"""IOC dataclasses, type enum, and value normalization.

Per brief v3 §6.1 the canonical IOC types are: ``ipv4``, ``ipv6``,
``domain``, ``url``, ``sha256``, ``sha1``, ``md5``, ``email``, ``cve``.

:class:`secops_term.intel.providers.base.IntelRecord` is the producer-side
type emitted by providers. :class:`IOC` and :class:`IocSource` here are the
storage-side types — what comes back out of the SQLite store. Normalization
is applied at upsert time so the ``UNIQUE(type, value)`` dedup key is
stable across providers (one provider's ``Example.COM.`` and another's
``example.com`` collapse to a single row).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit


class IOCType(StrEnum):
    """The canonical IOC types stored in the ``iocs`` table."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    EMAIL = "email"
    CVE = "cve"


KNOWN_TYPES = frozenset(t.value for t in IOCType)


# Common defang → fang replacements (longest matches first so "hxxps://"
# wins over "hxxp://").
_DEFANG_REPLACEMENTS = (
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("hxxps:", "https:"),
    ("hxxp:", "http:"),
    ("[://]", "://"),
    ("[:]", ":"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("{:}", ":"),
)

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


@dataclass(frozen=True)
class IOC:
    """One row from the ``iocs`` table."""

    id: int
    type: str
    value: str
    first_seen: datetime
    last_seen: datetime
    confidence: int | None
    tags: tuple[str, ...]


@dataclass(frozen=True)
class IocSource:
    """One row from the ``ioc_sources`` table."""

    ioc_id: int
    source: str
    source_ref: str | None
    context: str | None
    fetched_at: datetime


def refang(value: str) -> str:
    """Apply common defang→fang replacements (``hxxp``, ``[.]``, etc.).

    Idempotent — applying twice yields the same result.
    """
    out = value.strip()
    for src, dst in _DEFANG_REPLACEMENTS:
        out = out.replace(src, dst)
    return out


def normalize_value(type_: str, value: str) -> str:
    """Canonicalize ``value`` for the given ``type_``.

    Raises :class:`ValueError` on invalid input.
    """
    if type_ not in KNOWN_TYPES:
        raise ValueError(f"unknown IOC type: {type_!r}")
    raw = refang(value)
    if not raw:
        raise ValueError("empty IOC value")

    if type_ == IOCType.IPV4:
        return _canonical_ipv4(raw)
    if type_ == IOCType.IPV6:
        return _canonical_ipv6(raw)
    if type_ == IOCType.DOMAIN:
        return _canonical_domain(raw)
    if type_ == IOCType.URL:
        return _canonical_url(raw)
    if type_ == IOCType.SHA256:
        return _canonical_hash(raw, length=64)
    if type_ == IOCType.SHA1:
        return _canonical_hash(raw, length=40)
    if type_ == IOCType.MD5:
        return _canonical_hash(raw, length=32)
    if type_ == IOCType.EMAIL:
        return _canonical_email(raw)
    if type_ == IOCType.CVE:
        return _canonical_cve(raw)
    # KNOWN_TYPES guard above makes this unreachable, but mypy doesn't know.
    raise ValueError(f"unhandled IOC type: {type_!r}")


def _canonical_ipv4(s: str) -> str:
    try:
        addr = ipaddress.IPv4Address(s)
    except ValueError as exc:
        raise ValueError(f"invalid IPv4: {s!r}") from exc
    return str(addr)


def _canonical_ipv6(s: str) -> str:
    # Strip brackets if the caller passed `[2001:db8::1]` form.
    cleaned = s.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    try:
        addr = ipaddress.IPv6Address(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid IPv6: {s!r}") from exc
    return addr.compressed.lower()


def _canonical_domain(s: str) -> str:
    out = s.lower().rstrip(".")
    if not _DOMAIN_RE.match(out):
        raise ValueError(f"invalid domain: {s!r}")
    return out


def _canonical_url(s: str) -> str:
    parts = urlsplit(s)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https", "ftp"):
        raise ValueError(f"invalid URL scheme: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise ValueError(f"URL has no host: {s!r}")
    netloc = host.lower()
    if parts.port is not None and not (
        (scheme == "http" and parts.port == 80)
        or (scheme == "https" and parts.port == 443)
        or (scheme == "ftp" and parts.port == 21)
    ):
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))


def _canonical_hash(s: str, *, length: int) -> str:
    if len(s) != length:
        raise ValueError(f"expected {length}-char hash, got {len(s)}")
    if not _HEX_RE.match(s):
        raise ValueError(f"hash contains non-hex chars: {s!r}")
    return s.lower()


def _canonical_email(s: str) -> str:
    out = s.lower()
    if not _EMAIL_RE.match(out):
        raise ValueError(f"invalid email: {s!r}")
    return out


def _canonical_cve(s: str) -> str:
    out = s.upper()
    if not _CVE_RE.match(out):
        raise ValueError(f"invalid CVE: {s!r}")
    return out
