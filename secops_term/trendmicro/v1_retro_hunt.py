"""Vision One TMV1 retro-hunt query builder.

Per brief v3 §6.2: "V1 Search API with TMV1 query language. Map IOC types
to TMV1 fields." This module ships only the query builder for Phase 3.3 —
the V1-specific retro-hunt worker is deferred to Phase 6 polish (the
Chronicle worker pattern in :mod:`secops_term.chronicle.retro_hunt` is the
template; only the client + query builder differ).

TMV1 query mappings (using ``field:"value"`` syntax):

==========  ===============================================================
IOC type    TMV1 expression
==========  ===============================================================
ipv4/ipv6   ``dst:"X" OR src:"X" OR ipAddress:"X"``
domain      ``dstHost:"X" OR hostName:"X"``
url         ``request:"X"``
sha256      ``objectFileHashSha256:"X"``
sha1        ``objectFileHashSha1:"X"``
md5         ``objectFileHashMd5:"X"``
email       ``senderMailAddress:"X" OR recipientMailAddress:"X"``
cve         ``cveId:"X"``
==========  ===============================================================

Anything else raises :class:`UnsupportedIOCType`. Field names match the
documented V1 endpoint-activity schema; the user can verify against the
V1 console's Search panel after wiring up real credentials.
"""

from __future__ import annotations

# Platform string used in ``retro_hunt_jobs.platform`` for V1.
VISION_ONE_PLATFORM = "vision_one"


class UnsupportedIOCType(Exception):
    """The IOC type is not supported by the V1 TMV1 query builder."""


def build_tmv1_query(ioc_type: str, ioc_value: str) -> str:
    """Return a TMV1 query expression for the given IOC.

    Raises :class:`UnsupportedIOCType` if the IOC type isn't mapped.
    """
    val = _escape(ioc_value)
    if ioc_type in ("ipv4", "ipv6"):
        return f'dst:"{val}" OR src:"{val}" OR ipAddress:"{val}"'
    if ioc_type == "domain":
        return f'dstHost:"{val}" OR hostName:"{val}"'
    if ioc_type == "url":
        return f'request:"{val}"'
    if ioc_type == "sha256":
        return f'objectFileHashSha256:"{val}"'
    if ioc_type == "sha1":
        return f'objectFileHashSha1:"{val}"'
    if ioc_type == "md5":
        return f'objectFileHashMd5:"{val}"'
    if ioc_type == "email":
        return f'senderMailAddress:"{val}" OR recipientMailAddress:"{val}"'
    if ioc_type == "cve":
        return f'cveId:"{val}"'
    raise UnsupportedIOCType(f"no V1 TMV1 query for IOC type {ioc_type!r}")


def _escape(value: str) -> str:
    """Escape backslash and double-quote for TMV1 string literals.

    Defence in depth — ``intel.ioc.normalize_value`` already rejects values
    containing quotes for every supported type, so this is the same belt-
    and-suspenders pass we apply on the Chronicle side.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


__all__ = [
    "VISION_ONE_PLATFORM",
    "UnsupportedIOCType",
    "build_tmv1_query",
]
