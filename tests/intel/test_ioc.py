"""IOC normalization and refang."""

from __future__ import annotations

import pytest

from secops_term.intel import ioc

# refang


@pytest.mark.parametrize(
    ("defanged", "expected"),
    [
        ("hxxp://evil.com", "http://evil.com"),
        ("hxxps://evil.com", "https://evil.com"),
        ("evil[.]com", "evil.com"),
        ("evil(.)com", "evil.com"),
        ("evil.com", "evil.com"),
        ("8[.]8[.]8[.]8", "8.8.8.8"),
        ("hxxps://evil[.]com/path", "https://evil.com/path"),
    ],
)
def test_refang(defanged: str, expected: str) -> None:
    assert ioc.refang(defanged) == expected


def test_refang_idempotent() -> None:
    once = ioc.refang("hxxps://evil[.]com")
    twice = ioc.refang(once)
    assert once == twice


# IPv4


def test_ipv4_canonical() -> None:
    assert ioc.normalize_value("ipv4", "1.2.3.4") == "1.2.3.4"


def test_ipv4_strips_leading_zeros() -> None:
    # Python's ipaddress raises on leading zeros in 3.9+; we surface that.
    with pytest.raises(ValueError):
        ioc.normalize_value("ipv4", "01.02.03.04")


def test_ipv4_invalid_rejected() -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("ipv4", "256.0.0.1")


# IPv6


def test_ipv6_compressed() -> None:
    assert ioc.normalize_value("ipv6", "2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"


def test_ipv6_brackets_stripped() -> None:
    assert ioc.normalize_value("ipv6", "[2001:db8::1]") == "2001:db8::1"


def test_ipv6_lowercased() -> None:
    assert ioc.normalize_value("ipv6", "2001:DB8::1") == "2001:db8::1"


def test_ipv6_invalid_rejected() -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("ipv6", "not-an-ip")


# Domain


def test_domain_lowercased() -> None:
    assert ioc.normalize_value("domain", "Example.COM") == "example.com"


def test_domain_trailing_dot_stripped() -> None:
    assert ioc.normalize_value("domain", "example.com.") == "example.com"


def test_domain_defanged_input() -> None:
    assert ioc.normalize_value("domain", "evil[.]com") == "evil.com"


def test_domain_subdomain() -> None:
    assert ioc.normalize_value("domain", "Mail.Example.COM") == "mail.example.com"


@pytest.mark.parametrize(
    "bad",
    ["", "no-tld", "...", "-bad.com", "bad-.com", "x" * 300 + ".com"],
)
def test_domain_invalid_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("domain", bad)


# URL


def test_url_lowercases_scheme_and_host() -> None:
    assert (
        ioc.normalize_value("url", "HTTPS://Example.COM/Path?Q=1") == "https://example.com/Path?Q=1"
    )


def test_url_keeps_path_case() -> None:
    # Path / query are case-sensitive on the wire — preserve them verbatim.
    assert (
        ioc.normalize_value("url", "https://example.com/CaseSensitivePath")
        == "https://example.com/CaseSensitivePath"
    )


def test_url_drops_default_https_port() -> None:
    assert ioc.normalize_value("url", "https://example.com:443/foo") == "https://example.com/foo"


def test_url_keeps_non_default_port() -> None:
    assert (
        ioc.normalize_value("url", "https://example.com:8443/foo") == "https://example.com:8443/foo"
    )


def test_url_defanged() -> None:
    assert ioc.normalize_value("url", "hxxps://evil[.]com/malware") == "https://evil.com/malware"


def test_url_rejects_unknown_scheme() -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("url", "javascript:alert(1)")


def test_url_rejects_no_host() -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("url", "https:///path-only")


# Hashes


def test_sha256_lowercased() -> None:
    upper = "A" * 64
    assert ioc.normalize_value("sha256", upper) == "a" * 64


def test_sha1_length_enforced() -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("sha1", "a" * 39)


def test_md5_length_enforced() -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("md5", "a" * 33)


def test_hash_non_hex_rejected() -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("sha256", "z" * 64)


# Email


def test_email_lowercased() -> None:
    assert ioc.normalize_value("email", "Alice@Example.COM") == "alice@example.com"


def test_email_invalid_rejected() -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("email", "no-at-sign.example.com")


# CVE


def test_cve_uppercased() -> None:
    assert ioc.normalize_value("cve", "cve-2024-1234") == "CVE-2024-1234"


def test_cve_long_id_accepted() -> None:
    # CVE IDs can have 4+ digits in the ID portion.
    assert ioc.normalize_value("cve", "CVE-2024-1234567") == "CVE-2024-1234567"


def test_cve_invalid_rejected() -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("cve", "CVE-bogus")


# Cross-cutting


def test_unknown_type_rejected() -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("not-a-type", "anything")


def test_empty_value_rejected() -> None:
    with pytest.raises(ValueError):
        ioc.normalize_value("ipv4", "")


def test_known_types_includes_all_enum_members() -> None:
    assert ioc.KNOWN_TYPES == {t.value for t in ioc.IOCType}
