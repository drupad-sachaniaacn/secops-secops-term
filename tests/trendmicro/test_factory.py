"""Vision One factory — config + keyring → VisionOneClient."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from secops_term.core import secrets as secrets_mod
from secops_term.trendmicro import factory as factory_mod
from secops_term.trendmicro.vision_one import VisionOneClient, VisionOneError


def _make_fake_keyring(
    entries: dict[tuple[str, str], str] | None = None,
) -> ModuleType:
    class _Backend:
        pass

    backend = _Backend()
    store: dict[tuple[str, str], str] = dict(entries or {})

    def get_keyring() -> _Backend:
        return backend

    def set_password(service: str, key: str, value: str) -> None:
        store[(service, key)] = value

    def get_password(service: str, key: str) -> str | None:
        return store.get((service, key))

    def delete_password(service: str, key: str) -> None:
        store.pop((service, key), None)

    mod = ModuleType("fake_keyring")
    mod.get_keyring = get_keyring  # type: ignore[attr-defined]
    mod.set_password = set_password  # type: ignore[attr-defined]
    mod.get_password = get_password  # type: ignore[attr-defined]
    mod.delete_password = delete_password  # type: ignore[attr-defined]
    return mod


@pytest.fixture
def fake_secrets_with_token(tmp_root: Path) -> Iterator[None]:
    fake_kr = _make_fake_keyring({("secops-term:vision_one:default", "api_token"): "v1-token-test"})
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake_kr))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


@pytest.fixture
def fake_secrets_no_token(tmp_root: Path) -> Iterator[None]:
    fake_kr = _make_fake_keyring({})
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake_kr))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


# Returns None when block missing


def test_returns_none_for_empty_config(fake_secrets_no_token: None) -> None:
    assert factory_mod.build_vision_one_client(cfg_data={}) is None


def test_returns_none_for_no_vision_one_key(
    fake_secrets_no_token: None,
) -> None:
    assert factory_mod.build_vision_one_client(cfg_data={"unrelated": True}) is None


# Validation


def test_raises_when_block_is_not_a_table(
    fake_secrets_no_token: None,
) -> None:
    with pytest.raises(VisionOneError):
        factory_mod.build_vision_one_client(cfg_data={"vision_one": "not-a-table"})


def test_raises_when_base_url_is_not_string(
    fake_secrets_no_token: None,
) -> None:
    with pytest.raises(VisionOneError):
        factory_mod.build_vision_one_client(cfg_data={"vision_one": {"base_url": 42}})


def test_raises_when_base_url_empty_string(
    fake_secrets_no_token: None,
) -> None:
    with pytest.raises(VisionOneError):
        factory_mod.build_vision_one_client(cfg_data={"vision_one": {"base_url": "   "}})


def test_raises_when_token_missing(fake_secrets_no_token: None) -> None:
    with pytest.raises(VisionOneError) as exc_info:
        factory_mod.build_vision_one_client(cfg_data={"vision_one": {"allow_write": False}})
    assert "api_token" in str(exc_info.value)


# Happy path


def test_builds_client_with_default_base_url(
    fake_secrets_with_token: None,
) -> None:
    client = factory_mod.build_vision_one_client(cfg_data={"vision_one": {"allow_write": False}})
    assert client is not None
    assert isinstance(client, VisionOneClient)
    assert client.cfg.api_token == "v1-token-test"
    assert client.base_url == "https://api.xdr.trendmicro.com"
    assert client.cfg.allow_write is False


def test_builds_client_with_base_url_override(
    fake_secrets_with_token: None,
) -> None:
    client = factory_mod.build_vision_one_client(
        cfg_data={"vision_one": {"base_url": "https://custom-v1.example.com"}}
    )
    assert client is not None
    assert client.base_url == "https://custom-v1.example.com"


def test_per_instance_keyring_lookup(tmp_root: Path) -> None:
    fake_kr = _make_fake_keyring(
        {("secops-term:vision_one:secondary", "api_token"): "secondary-token"}
    )
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake_kr))
    try:
        with pytest.raises(VisionOneError):
            factory_mod.build_vision_one_client(cfg_data={"vision_one": {}}, instance="default")
        client = factory_mod.build_vision_one_client(
            cfg_data={"vision_one": {}}, instance="secondary"
        )
        assert client is not None
        assert client.cfg.api_token == "secondary-token"
    finally:
        secrets_mod.reset_manager_for_tests()
