"""STIX 2.1 bundle exporter — unit tests."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from secops_term.intel.ioc import IOC
from secops_term.intel.stix_export import (
    export_bundle,
    export_bundle_json,
    ioc_to_stix_object,
    stix_id_for,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _ioc(
    type_: str,
    value: str,
    ioc_id: int = 1,
    confidence: int | None = None,
    tags: tuple[str, ...] = (),
) -> IOC:
    now = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
    return IOC(
        id=ioc_id,
        type=type_,
        value=value,
        first_seen=now,
        last_seen=now,
        confidence=confidence,
        tags=tags,
    )


# ---------------------------------------------------------------------------
# stix_id_for
# ---------------------------------------------------------------------------


def test_stix_id_deterministic() -> None:
    """Same type + seed always produces the same ID."""
    id1 = stix_id_for("ipv4-addr", "ipv4:1.2.3.4")
    id2 = stix_id_for("ipv4-addr", "ipv4:1.2.3.4")
    assert id1 == id2


def test_stix_id_format() -> None:
    """ID has the form '<type>--<uuid4-like-string>'."""
    stix_id = stix_id_for("domain-name", "domain:evil.example.com")
    prefix, uid = stix_id.split("--", 1)
    assert prefix == "domain-name"
    assert _UUID_RE.match(uid)


def test_stix_id_different_for_different_seeds() -> None:
    id1 = stix_id_for("ipv4-addr", "ipv4:1.2.3.4")
    id2 = stix_id_for("ipv4-addr", "ipv4:5.6.7.8")
    assert id1 != id2


# ---------------------------------------------------------------------------
# ioc_to_stix_object — per type
# ---------------------------------------------------------------------------


def test_ipv4_maps_to_ipv4_addr() -> None:
    obj = ioc_to_stix_object(_ioc("ipv4", "1.2.3.4"))
    assert obj is not None
    assert obj["type"] == "ipv4-addr"
    assert obj["value"] == "1.2.3.4"
    assert obj["spec_version"] == "2.1"
    assert obj["id"].startswith("ipv4-addr--")


def test_ipv6_maps_to_ipv6_addr() -> None:
    obj = ioc_to_stix_object(_ioc("ipv6", "2001:db8::1"))
    assert obj is not None
    assert obj["type"] == "ipv6-addr"
    assert obj["value"] == "2001:db8::1"


def test_domain_maps_to_domain_name() -> None:
    obj = ioc_to_stix_object(_ioc("domain", "evil.example.com"))
    assert obj is not None
    assert obj["type"] == "domain-name"
    assert obj["value"] == "evil.example.com"


def test_url_maps_to_url_object() -> None:
    obj = ioc_to_stix_object(_ioc("url", "https://evil.example.com/payload"))
    assert obj is not None
    assert obj["type"] == "url"
    assert obj["value"] == "https://evil.example.com/payload"


def test_sha256_maps_to_file_with_hashes() -> None:
    sha256 = "a" * 64
    obj = ioc_to_stix_object(_ioc("sha256", sha256))
    assert obj is not None
    assert obj["type"] == "file"
    assert obj["hashes"]["SHA-256"] == sha256
    assert obj["id"].startswith("file--")


def test_sha1_maps_to_file_with_hashes() -> None:
    sha1 = "b" * 40
    obj = ioc_to_stix_object(_ioc("sha1", sha1))
    assert obj is not None
    assert obj["type"] == "file"
    assert obj["hashes"]["SHA-1"] == sha1


def test_md5_maps_to_file_with_hashes() -> None:
    md5 = "c" * 32
    obj = ioc_to_stix_object(_ioc("md5", md5))
    assert obj is not None
    assert obj["type"] == "file"
    assert obj["hashes"]["MD5"] == md5


def test_email_maps_to_email_addr() -> None:
    obj = ioc_to_stix_object(_ioc("email", "attacker@evil.example.com"))
    assert obj is not None
    assert obj["type"] == "email-addr"
    assert obj["value"] == "attacker@evil.example.com"


def test_cve_maps_to_vulnerability() -> None:
    obj = ioc_to_stix_object(_ioc("cve", "CVE-2024-12345"))
    assert obj is not None
    assert obj["type"] == "vulnerability"
    assert obj["name"] == "CVE-2024-12345"
    assert obj["id"].startswith("vulnerability--")
    ext_refs = obj["external_references"]
    assert len(ext_refs) == 1
    assert ext_refs[0]["external_id"] == "CVE-2024-12345"
    assert "nvd.nist.gov" in ext_refs[0]["url"]


# ---------------------------------------------------------------------------
# export_bundle
# ---------------------------------------------------------------------------


def test_bundle_structure() -> None:
    iocs = [_ioc("ipv4", "1.2.3.4"), _ioc("domain", "evil.example.com", ioc_id=2)]
    bundle = export_bundle(iocs)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert len(bundle["objects"]) == 2


def test_bundle_id_is_random_per_call() -> None:
    iocs = [_ioc("ipv4", "1.2.3.4")]
    b1 = export_bundle(iocs)
    b2 = export_bundle(iocs)
    assert b1["id"] != b2["id"]


def test_empty_bundle() -> None:
    bundle = export_bundle([])
    assert bundle["type"] == "bundle"
    assert bundle["objects"] == []


def test_dedup_same_stix_id() -> None:
    """The same IOC value appearing twice yields one STIX object in the bundle."""
    ioc1 = _ioc("ipv4", "1.2.3.4", ioc_id=1)
    ioc2 = _ioc("ipv4", "1.2.3.4", ioc_id=2)  # same value, different store id
    bundle = export_bundle([ioc1, ioc2])
    assert len(bundle["objects"]) == 1


def test_all_nine_types_produce_objects() -> None:
    iocs = [
        _ioc("ipv4", "1.2.3.4", ioc_id=1),
        _ioc("ipv6", "::1", ioc_id=2),
        _ioc("domain", "evil.com", ioc_id=3),
        _ioc("url", "https://evil.com/", ioc_id=4),
        _ioc("sha256", "a" * 64, ioc_id=5),
        _ioc("sha1", "b" * 40, ioc_id=6),
        _ioc("md5", "c" * 32, ioc_id=7),
        _ioc("email", "x@evil.com", ioc_id=8),
        _ioc("cve", "CVE-2024-99999", ioc_id=9),
    ]
    bundle = export_bundle(iocs)
    assert len(bundle["objects"]) == 9


def test_export_bundle_json_is_valid_json() -> None:
    iocs = [_ioc("ipv4", "1.2.3.4")]
    raw = export_bundle_json(iocs)
    parsed = json.loads(raw)
    assert parsed["type"] == "bundle"


def test_stix_timestamp_format() -> None:
    """CVE vulnerability objects carry STIX-format timestamps."""
    obj = ioc_to_stix_object(_ioc("cve", "CVE-2024-00001"))
    assert obj is not None
    # Must match YYYY-MM-DDTHH:MM:SS.<ms>Z
    ts_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
    assert ts_re.match(obj["created"])
    assert ts_re.match(obj["modified"])
