"""``config_io``: TOML write + read round-trip, masking, ACL enforcement."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from secops_term.core import config_io, paths


def test_load_returns_empty_when_missing(tmp_root: Path) -> None:
    assert config_io.load_config() == {}


def test_save_then_load_round_trip(tmp_root: Path) -> None:
    data = {
        "schema_version": 1,
        "chronicle": {
            "customer_id": "abc-123",
            "region": "us",
            "allow_write": False,
        },
        "intel_providers": {
            "abuse_ch": {
                "default": {"enabled": True, "sub_feeds": ["urlhaus", "threatfox"]},
            },
        },
    }
    config_io.save_config(data)
    loaded = config_io.load_config()
    assert loaded == data


def test_save_uses_restrictive_acl(tmp_root: Path) -> None:
    config_io.save_config({"chronicle": {"customer_id": "abc"}})
    if os.name != "nt":
        mode = config_io.config_path().stat().st_mode & 0o777
        assert mode == 0o600


def test_load_rejects_permissive_acl(tmp_root: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode test")
    config_io.save_config({"chronicle": {"customer_id": "abc"}})
    config_io.config_path().chmod(0o644)
    with pytest.raises(paths.RestrictiveACLError):
        config_io.load_config()


def test_load_rejects_malformed_toml(tmp_root: Path) -> None:
    paths.ensure_root_initialized()
    p = config_io.config_path()
    p.write_text("not = valid TOML\nfoo bar baz", encoding="utf-8")
    paths.apply_restrictive_acl(p)
    with pytest.raises(config_io.ConfigError):
        config_io.load_config()


def test_dump_handles_strings_with_special_chars() -> None:
    data = {"x": {"path": r"C:\Users\me", "quote": 'a "quoted" string'}}
    text = config_io._dump_toml(data)
    assert r"C:\\Users\\me" in text
    assert r"a \"quoted\" string" in text


def test_dump_lists_of_strings() -> None:
    data = {"x": {"items": ["a", "b", "c"]}}
    text = config_io._dump_toml(data)
    assert '["a", "b", "c"]' in text


def test_dump_omits_none_values() -> None:
    data = {"x": {"a": 1, "b": None, "c": 2}}
    text = config_io._dump_toml(data)
    assert "a = 1" in text
    assert "c = 2" in text
    assert "b =" not in text


def test_dump_unsupported_type_raises() -> None:
    data = {"x": {"bad": object()}}
    with pytest.raises(TypeError):
        config_io._dump_toml(data)


def test_mask_secret_long() -> None:
    assert config_io.mask_secret("sk-supersecret-AAAA") == "sk…••••AAAA"


def test_mask_secret_short() -> None:
    assert config_io.mask_secret("ab") == "••"
    assert config_io.mask_secret("") == ""
