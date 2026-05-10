"""SSRF guard rejects every shape of forbidden address."""

from __future__ import annotations

import socket

import pytest

from secops_term.core import url_guard

pytestmark = pytest.mark.security


# Scheme allowlist


def test_http_rejected_by_default() -> None:
    with pytest.raises(url_guard.SchemeRejected):
        url_guard.validate_url("http://example.com/")


def test_http_allowed_with_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_guard, "_resolve_all", lambda h, p: [("8.8.8.8", socket.AF_INET)])
    result = url_guard.validate_url("http://example.com/", allow_insecure=True)
    assert result.scheme == "http"


def test_file_scheme_rejected() -> None:
    with pytest.raises(url_guard.SchemeRejected):
        url_guard.validate_url("file:///etc/passwd")


def test_gopher_scheme_rejected() -> None:
    with pytest.raises(url_guard.SchemeRejected):
        url_guard.validate_url("gopher://attacker.example.com/")


def test_javascript_scheme_rejected() -> None:
    with pytest.raises(url_guard.SchemeRejected):
        url_guard.validate_url("javascript:alert(1)")


def test_url_with_no_host() -> None:
    with pytest.raises(url_guard.URLGuardError):
        url_guard.validate_url("https:///path-only")


# Forbidden address ranges (IP literals — no DNS involvement)


def test_loopback_ipv4_rejected() -> None:
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://127.0.0.1/")


def test_loopback_ipv6_rejected() -> None:
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://[::1]/")


def test_rfc1918_10_rejected() -> None:
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://10.0.0.1/")


def test_rfc1918_172_rejected() -> None:
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://172.16.0.1/")


def test_rfc1918_192_168_rejected() -> None:
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://192.168.1.1/")


def test_link_local_aws_metadata_rejected() -> None:
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://169.254.169.254/latest/meta-data/")


def test_link_local_ipv6_rejected() -> None:
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://[fe80::1]/")


def test_unique_local_ipv6_rejected() -> None:
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://[fc00::1]/")


def test_cgnat_rejected() -> None:
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://100.64.0.1/")


def test_unspecified_rejected() -> None:
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://0.0.0.0/")


def test_multicast_rejected() -> None:
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://224.0.0.1/")


# Hostname resolution


def test_unresolvable_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_guard, "_resolve_all", lambda h, p: [])
    with pytest.raises(url_guard.UnresolvableHost):
        url_guard.validate_url("https://will-not-resolve.example/")


def test_localhost_hostname_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regardless of what /etc/hosts maps "localhost" to, it must be rejected.
    monkeypatch.setattr(url_guard, "_resolve_all", lambda h, p: [("127.0.0.1", socket.AF_INET)])
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://localhost/")


def test_dns_rebinding_any_private_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    # If DNS returns multiple addresses and ANY is private, reject.
    monkeypatch.setattr(
        url_guard,
        "_resolve_all",
        lambda h, p: [
            ("8.8.8.8", socket.AF_INET),
            ("127.0.0.1", socket.AF_INET),  # poisoned A record
        ],
    )
    with pytest.raises(url_guard.PrivateAddress):
        url_guard.validate_url("https://attacker.example.com/")


# Pinned IP and host header


def test_validated_url_pins_first_resolved_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        url_guard,
        "_resolve_all",
        lambda h, p: [
            ("93.184.216.34", socket.AF_INET),
            ("93.184.216.35", socket.AF_INET),
        ],
    )
    result = url_guard.validate_url("https://example.com/foo?bar=1")
    assert result.pinned_ip == "93.184.216.34"
    assert result.url_with_pinned_ip == "https://93.184.216.34/foo?bar=1"
    assert result.host_header == "example.com"


def test_validated_url_preserves_path_query_fragment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(url_guard, "_resolve_all", lambda h, p: [("8.8.8.8", socket.AF_INET)])
    result = url_guard.validate_url("https://example.com/api/v1/foo?key=value&q=2#section")
    assert result.path_query_fragment == "/api/v1/foo?key=value&q=2#section"


def test_validated_url_non_default_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(url_guard, "_resolve_all", lambda h, p: [("8.8.8.8", socket.AF_INET)])
    result = url_guard.validate_url("https://example.com:8443/foo")
    assert result.port == 8443
    assert result.host_header == "example.com:8443"
    assert result.url_with_pinned_ip == "https://8.8.8.8:8443/foo"


def test_validated_url_ipv6_bracketed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        url_guard,
        "_resolve_all",
        lambda h, p: [("2001:4860:4860::8888", socket.AF_INET6)],
    )
    result = url_guard.validate_url("https://dns.google/foo")
    assert result.is_ipv6 is True
    assert result.url_with_pinned_ip == "https://[2001:4860:4860::8888]/foo"
