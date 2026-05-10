"""Deep Security factory — config + keyring → DeepSecurityClient."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from secops_term.core import secrets as secrets_mod
from secops_term.trendmicro import factory as factory_mod
from secops_term.trendmicro.deep_security import (
    DeepSecurityClient,
    DeepSecurityError,
)


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
def fake_secrets_with_key(tmp_root: Path) -> Iterator[None]:
    fake_kr = _make_fake_keyring({("secops-term:deep_security:default", "api_key"): "ds-key-test"})
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake_kr))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


@pytest.fixture
def fake_secrets_no_key(tmp_root: Path) -> Iterator[None]:
    fake_kr = _make_fake_keyring({})
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake_kr))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


# Returns None when block missing


def test_returns_none_for_empty_config(fake_secrets_no_key: None) -> None:
    assert factory_mod.build_deep_security_client(cfg_data={}) is None


def test_returns_none_for_no_deep_security_key(
    fake_secrets_no_key: None,
) -> None:
    assert factory_mod.build_deep_security_client(cfg_data={"unrelated": True}) is None


# Validation


def test_raises_when_block_is_not_a_table(
    fake_secrets_no_key: None,
) -> None:
    with pytest.raises(DeepSecurityError):
        factory_mod.build_deep_security_client(cfg_data={"deep_security": "not-a-table"})


def test_raises_when_base_url_missing_uses_dsaas_default(
    fake_secrets_with_key: None,
) -> None:
    """Default to DSaaS URL when base_url is omitted."""
    client = factory_mod.build_deep_security_client(cfg_data={"deep_security": {}})
    assert client is not None
    assert client.base_url == "https://app.deepsecurity.trendmicro.com"


def test_raises_when_base_url_empty_string(
    fake_secrets_no_key: None,
) -> None:
    with pytest.raises(DeepSecurityError):
        factory_mod.build_deep_security_client(cfg_data={"deep_security": {"base_url": "   "}})


def test_raises_when_base_url_not_string(fake_secrets_no_key: None) -> None:
    with pytest.raises(DeepSecurityError):
        factory_mod.build_deep_security_client(cfg_data={"deep_security": {"base_url": 42}})


def test_raises_on_unknown_deployment_type(
    fake_secrets_no_key: None,
) -> None:
    with pytest.raises(DeepSecurityError):
        factory_mod.build_deep_security_client(
            cfg_data={
                "deep_security": {
                    "base_url": "https://x",
                    "deployment_type": "cloud",
                }
            }
        )


def test_raises_when_deployment_type_not_string(
    fake_secrets_no_key: None,
) -> None:
    with pytest.raises(DeepSecurityError):
        factory_mod.build_deep_security_client(
            cfg_data={
                "deep_security": {
                    "base_url": "https://x",
                    "deployment_type": 42,
                }
            }
        )


def test_raises_when_api_key_missing(fake_secrets_no_key: None) -> None:
    with pytest.raises(DeepSecurityError) as exc_info:
        factory_mod.build_deep_security_client(
            cfg_data={"deep_security": {"base_url": "https://x"}}
        )
    assert "api_key" in str(exc_info.value)


# Happy paths


def test_builds_dsaas_client(fake_secrets_with_key: None) -> None:
    client = factory_mod.build_deep_security_client(
        cfg_data={"deep_security": {"deployment_type": "dsaas"}}
    )
    assert client is not None
    assert isinstance(client, DeepSecurityClient)
    assert client.cfg.api_key == "ds-key-test"
    assert client.cfg.deployment_type == "dsaas"
    assert client.base_url == "https://app.deepsecurity.trendmicro.com"


def test_builds_on_prem_client(fake_secrets_with_key: None) -> None:
    client = factory_mod.build_deep_security_client(
        cfg_data={
            "deep_security": {
                "base_url": "https://dsm.internal.example.com:4119",
                "deployment_type": "on_prem",
            }
        }
    )
    assert client is not None
    assert client.cfg.deployment_type == "on_prem"
    assert client.base_url == "https://dsm.internal.example.com:4119"


def test_per_instance_keyring_lookup(tmp_root: Path) -> None:
    fake_kr = _make_fake_keyring({("secops-term:deep_security:secondary", "api_key"): "second-key"})
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake_kr))
    try:
        with pytest.raises(DeepSecurityError):
            factory_mod.build_deep_security_client(
                cfg_data={"deep_security": {}}, instance="default"
            )
        client = factory_mod.build_deep_security_client(
            cfg_data={"deep_security": {}}, instance="secondary"
        )
        assert client is not None
        assert client.cfg.api_key == "second-key"
    finally:
        secrets_mod.reset_manager_for_tests()
