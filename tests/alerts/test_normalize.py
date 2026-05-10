"""Per-source alert normalizers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from secops_term.alerts import normalize

# Chronicle


def test_chronicle_basic_alert() -> None:
    payload = {
        "id": "chr-alert-1",
        "ruleName": "Suspicious PowerShell",
        "severity": "High",
        "detectionTime": "2026-06-01T12:00:00Z",
        "principal": {"hostname": "WIN-01", "ip": ["10.0.0.5"]},
        "target": {"ip": ["8.8.8.8"]},
    }
    alert = normalize.normalize_chronicle_alert(payload)
    assert alert.id == "chr-alert-1"
    assert alert.source == "chronicle"
    assert alert.severity == "high"
    assert alert.title == "Suspicious PowerShell"
    assert alert.dedupe_key == "chronicle:chr-alert-1"
    entity_pairs = {(e.type, e.value) for e in alert.entities}
    assert ("host", "WIN-01") in entity_pairs
    # Note: 10.0.0.5 is private but normalize doesn't filter — that's the
    # url_guard's job, not the alert pipeline's.
    assert ("ip", "8.8.8.8") in entity_pairs


def test_chronicle_unknown_severity_falls_back_medium() -> None:
    payload = {"id": "x", "severity": "WTF"}
    assert normalize.normalize_chronicle_alert(payload).severity == "medium"


def test_chronicle_missing_id_uses_fallback() -> None:
    payload = {"ruleName": "x"}
    alert = normalize.normalize_chronicle_alert(payload)
    assert alert.id.startswith("chronicle-")
    assert alert.dedupe_key.startswith("chronicle:")


def test_chronicle_z_suffix_timestamp() -> None:
    payload = {"id": "x", "detectionTime": "2026-06-01T12:00:00Z"}
    alert = normalize.normalize_chronicle_alert(payload)
    assert alert.detected_at == datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


def test_chronicle_invalid_timestamp_falls_back_to_now() -> None:
    payload = {"id": "x", "detectionTime": "not-a-date"}
    alert = normalize.normalize_chronicle_alert(payload)
    assert (datetime.now(UTC) - alert.detected_at) < timedelta(seconds=10)


def test_chronicle_entities_dedupe() -> None:
    payload = {
        "id": "x",
        "principal": {"ip": ["1.1.1.1", "1.1.1.1"]},
        "target": {"ip": "1.1.1.1"},
    }
    alert = normalize.normalize_chronicle_alert(payload)
    ip_entities = [e for e in alert.entities if e.type == "ip"]
    assert len(ip_entities) == 1


# Vision One


def test_vision_one_basic_alert() -> None:
    payload = {
        "id": "v1-alert-99",
        "model": "Suspicious DNS Query",
        "severity": "medium",
        "createdDateTime": "2026-06-01T08:00:00Z",
        "endpointHostName": "MAC-12",
        "ipAddress": "8.8.8.8",
    }
    alert = normalize.normalize_vision_one_alert(payload)
    assert alert.source == "vision_one"
    assert alert.severity == "medium"
    assert alert.title == "Suspicious DNS Query"
    pairs = {(e.type, e.value) for e in alert.entities}
    assert ("host", "MAC-12") in pairs
    assert ("ip", "8.8.8.8") in pairs


def test_vision_one_impact_scope_entities() -> None:
    payload = {
        "id": "x",
        "impactScope": {
            "entities": [
                {"entityType": "host", "entityValue": "WIN-01"},
                {"entityType": "user", "entityValue": "alice"},
                {"entityType": "ipAddress", "entityValue": "1.1.1.1"},
                {"entityType": "unknown", "entityValue": "skip"},
            ]
        },
    }
    alert = normalize.normalize_vision_one_alert(payload)
    pairs = {(e.type, e.value) for e in alert.entities}
    assert ("host", "WIN-01") in pairs
    assert ("user", "alice") in pairs
    assert ("ip", "1.1.1.1") in pairs


def test_vision_one_missing_severity_falls_back_medium() -> None:
    payload = {"id": "x"}
    assert normalize.normalize_vision_one_alert(payload).severity == "medium"


# Deep Security


def test_deep_security_basic_alert() -> None:
    payload = {
        "ID": 42,
        "name": "Anti-Malware Detected",
        "severity": "high",
        "alertedTime": "2026-06-01T01:00:00Z",
        "computerName": "ESX-01",
    }
    alert = normalize.normalize_deep_security_alert(payload)
    assert alert.source == "deep_security"
    assert alert.id == "42"
    assert alert.severity == "high"
    pairs = {(e.type, e.value) for e in alert.entities}
    assert ("host", "ESX-01") in pairs


def test_deep_security_numeric_severity_high() -> None:
    payload = {"ID": "x", "severity": 80}
    assert normalize.normalize_deep_security_alert(payload).severity == "high"


def test_deep_security_numeric_severity_critical() -> None:
    payload = {"ID": "x", "severity": 95}
    assert normalize.normalize_deep_security_alert(payload).severity == "critical"


def test_deep_security_numeric_severity_low() -> None:
    payload = {"ID": "x", "severity": 25}
    assert normalize.normalize_deep_security_alert(payload).severity == "low"


def test_deep_security_unknown_severity_falls_back_medium() -> None:
    payload = {"ID": "x", "severity": "weird"}
    assert normalize.normalize_deep_security_alert(payload).severity == "medium"


# title_signature


def test_title_signature_strips_digits_and_normalizes() -> None:
    sig_a = normalize.title_signature("Login failure on host123 at 10:00")
    sig_b = normalize.title_signature("Login failure on host456 at 11:30")
    assert sig_a == sig_b


def test_title_signature_lowercases() -> None:
    assert normalize.title_signature("ABC") == normalize.title_signature("abc")


def test_title_signature_collapses_whitespace() -> None:
    assert normalize.title_signature("a   b   c") == "a b c"
