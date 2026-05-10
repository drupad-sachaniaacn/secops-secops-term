"""SSRF guard for user-configurable URLs.

Per brief v3 §3.5.4. Any URL coming from user-configurable input — webhook
targets, custom RSS sources, scraping targets, generic-JSON notifier endpoints —
must pass through :func:`validate_url` before any network call.

The guard:

1. Parses the URL with ``urllib.parse``. Requires ``https`` (or ``http`` only
   when the caller passes ``allow_insecure=True``, used for opt-in RSS feeds).
2. Resolves the hostname via ``socket.getaddrinfo``. Takes **all** returned
   addresses (DNS round-robin, A + AAAA records, etc.).
3. Rejects if **any** resolved address is in: ``10/8``, ``172.16/12``,
   ``192.168/16``, ``127/8``, ``169.254/16``, ``100.64/10`` (CGNAT),
   ``0.0.0.0/8``, ``::1/128``, ``fc00::/7``, ``fe80::/10``, multicast, or
   has non-global scope.
4. Returns a :class:`ValidatedURL` with the pinned IP that callers MUST
   connect to (and the ``Host`` header that MUST be set for SNI/TLS),
   preventing DNS rebinding between validation and connect.

Allow/deny decisions are intended to be logged via the audit chain by
callers (this module deliberately has no logging side-effects).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class URLGuardError(Exception):
    """Base class for URL-guard violations."""


class SchemeRejected(URLGuardError):
    """URL scheme is not in the allowlist."""


class UnresolvableHost(URLGuardError):
    """Hostname did not resolve to any address."""


class PrivateAddress(URLGuardError):
    """Resolved address is in a forbidden range (private/loopback/link-local/etc)."""


@dataclass(frozen=True)
class ValidatedURL:
    """A URL that passed SSRF validation.

    ``pinned_ip`` is the address callers MUST connect to. ``host_header`` is
    the ``Host`` value that MUST be sent for SNI/TLS. Connecting to the
    hostname directly (and re-resolving via DNS) defeats the rebinding
    mitigation.
    """

    original: str
    scheme: str
    host: str
    port: int
    path_query_fragment: str
    pinned_ip: str
    is_ipv6: bool

    @property
    def host_header(self) -> str:
        """Host header value: hostname[:port] (port omitted if default)."""
        if (self.scheme == "https" and self.port == 443) or (
            self.scheme == "http" and self.port == 80
        ):
            return self.host
        return f"{self.host}:{self.port}"

    @property
    def url_with_pinned_ip(self) -> str:
        """Reassembled URL using the pinned IP (literal-bracketed for IPv6)."""
        host_part = f"[{self.pinned_ip}]" if self.is_ipv6 else self.pinned_ip
        if (self.scheme == "https" and self.port == 443) or (
            self.scheme == "http" and self.port == 80
        ):
            netloc = host_part
        else:
            netloc = f"{host_part}:{self.port}"
        return f"{self.scheme}://{netloc}{self.path_query_fragment}"


def validate_url(url: str, *, allow_insecure: bool = False) -> ValidatedURL:
    """Validate a user-supplied URL and return a pinned-IP :class:`ValidatedURL`.

    Rejects: non-http(s) schemes, ``http`` when ``allow_insecure=False``,
    hostnames that resolve to any private/loopback/multicast/non-global
    address.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme == "https":
        pass
    elif scheme == "http":
        if not allow_insecure:
            raise SchemeRejected(
                "http is not allowed; pass allow_insecure=True for opt-in RSS sources"
            )
    else:
        raise SchemeRejected(f"scheme {scheme!r} not allowed; only https (or http with opt-in)")

    host = parts.hostname
    if not host:
        raise URLGuardError(f"URL has no host: {url!r}")
    port = parts.port if parts.port is not None else (443 if scheme == "https" else 80)

    # Reconstruct the path+query+fragment portion (avoid manual slicing pitfalls).
    path = parts.path or ""
    pqf_parts = [path]
    if parts.query:
        pqf_parts.append(f"?{parts.query}")
    if parts.fragment:
        pqf_parts.append(f"#{parts.fragment}")
    path_query_fragment = "".join(pqf_parts)

    resolved = _resolve_all(host, port)
    if not resolved:
        raise UnresolvableHost(f"no addresses for {host!r}")

    for ip_str, _family in resolved:
        ip_obj = ipaddress.ip_address(ip_str)
        if not _is_routable(ip_obj):
            raise PrivateAddress(
                f"{host} resolves to forbidden address {ip_str} (one of {len(resolved)} resolved)"
            )

    pinned_ip, family = resolved[0]
    is_ipv6 = family == socket.AF_INET6

    return ValidatedURL(
        original=url,
        scheme=scheme,
        host=host,
        port=port,
        path_query_fragment=path_query_fragment,
        pinned_ip=pinned_ip,
        is_ipv6=is_ipv6,
    )


def _resolve_all(host: str, port: int) -> list[tuple[str, int]]:
    """Resolve ``host`` to a deduplicated list of ``(ip_str, family)`` tuples."""
    out: list[tuple[str, int]] = []
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return out
    seen: set[str] = set()
    for family, _socktype, _proto, _canon, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        # sockaddr is (host, port) for AF_INET and (host, port, flowinfo, scopeid)
        # for AF_INET6; the first element is always the address string.
        ip_value = sockaddr[0]
        if not isinstance(ip_value, str):
            continue
        if ip_value in seen:
            continue
        seen.add(ip_value)
        out.append((ip_value, family))
    return out


def _is_routable(ip: IPAddress) -> bool:
    """Return ``True`` iff ``ip`` is safe to connect to from a public-internet client.

    Rejects private (RFC1918, ULA), loopback, link-local, multicast,
    reserved, unspecified, and CGNAT (100.64.0.0/10).
    """
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        # CGNAT may not be flagged by is_private on older Python.
        cgnat_lo = ipaddress.IPv4Address("100.64.0.0")
        cgnat_hi = ipaddress.IPv4Address("100.127.255.255")
        if cgnat_lo <= ip <= cgnat_hi:
            return False
    return True
