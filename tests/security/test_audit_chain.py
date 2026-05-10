"""Hash-chained audit log: tamper detection, redaction at emit, rotation chains."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secops_term.core import audit, redact

pytestmark = pytest.mark.security


def test_genesis_chain(tmp_root: Path) -> None:
    log = audit.AuditLogger(path=tmp_root / "audit.jsonl")
    e1 = log.emit({"event": "config.set", "provider": "vt"})
    e2 = log.emit({"event": "config.test", "provider": "vt"})
    assert e1.seq == 1
    assert e1.prev_hash == audit.GENESIS_HASH
    assert e2.seq == 2
    assert e2.prev_hash == e1.hash


def test_verify_passes_on_clean_chain(tmp_root: Path) -> None:
    log = audit.AuditLogger(path=tmp_root / "audit.jsonl")
    for i in range(5):
        log.emit({"event": "probe", "i": i, "kind": "probe"})
    files, entries = audit.verify_chain(root=tmp_root)
    assert files == 1
    assert entries == 5


def test_verify_detects_tampered_entry(tmp_root: Path) -> None:
    p = tmp_root / "audit.jsonl"
    log = audit.AuditLogger(path=p)
    log.emit({"event": "first"})
    log.emit({"event": "second"})
    log.emit({"event": "third"})
    lines = p.read_text(encoding="utf-8").splitlines()
    parsed = json.loads(lines[1])
    parsed["entry"] = {"event": "TAMPERED"}
    lines[1] = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(audit.ChainBroken):
        audit.verify_chain(root=tmp_root)


def test_verify_detects_reordered_entries(tmp_root: Path) -> None:
    p = tmp_root / "audit.jsonl"
    log = audit.AuditLogger(path=p)
    log.emit({"event": "a"})
    log.emit({"event": "b"})
    log.emit({"event": "c"})
    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text(lines[1] + "\n" + lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
    with pytest.raises(audit.ChainBroken):
        audit.verify_chain(root=tmp_root)


def test_redaction_at_emit(tmp_root: Path) -> None:
    redact.taint("sk-supersecret-AAAA", "vt:default:api_key")
    log = audit.AuditLogger(path=tmp_root / "audit.jsonl")
    log.emit({"event": "auth", "value": "the key was sk-supersecret-AAAA leaked"})
    text = (tmp_root / "audit.jsonl").read_text(encoding="utf-8")
    assert "supersecret" not in text
    assert "<redacted:vt:default:api_key>" in text


def test_chain_continues_across_rotation(tmp_root: Path) -> None:
    # Tiny rotation threshold to force frequent rotations.
    log = audit.AuditLogger(path=tmp_root / "audit.jsonl", rotation_size=64)
    for i in range(20):
        log.emit({"event": "fill", "i": i, "padding": "x" * 16})
    files, entries = audit.verify_chain(root=tmp_root)
    assert files >= 2  # confirmed rotation occurred
    assert entries >= 20


def test_canonical_json_rejects_nan() -> None:
    with pytest.raises(ValueError):
        audit.canonical_json({"x": float("nan")})


def test_canonical_json_rejects_infinity() -> None:
    with pytest.raises(ValueError):
        audit.canonical_json({"x": float("inf")})


def test_canonical_json_sorts_keys() -> None:
    out = audit.canonical_json({"b": 2, "a": 1})
    assert out == '{"a":1,"b":2}'


def test_chain_recovers_state_on_reopen(tmp_root: Path) -> None:
    p = tmp_root / "audit.jsonl"
    log1 = audit.AuditLogger(path=p)
    log1.emit({"event": "first"})
    log1.emit({"event": "second"})
    # Simulate process restart: new logger reads tail to find seq + prev_hash.
    log2 = audit.AuditLogger(path=p)
    e3 = log2.emit({"event": "third"})
    assert e3.seq == 3
    files, entries = audit.verify_chain(root=tmp_root)
    assert files == 1
    assert entries == 3
