"""Chronicle factory: walk config + keyring → ChronicleClient."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from secops_term.chronicle import factory as factory_mod
from secops_term.chronicle.client import ChronicleClient, ChronicleError
from secops_term.core import secrets as secrets_mod

_FAKE_SA_JSON = {
    "type": "service_account",
    "client_email": "robot@project.iam.gserviceaccount.com",
    "private_key": ("-----BEGIN PRIVATE KEY-----\nfake-key-for-tests\n-----END PRIVATE KEY-----\n"),
}


def _make_fake_keyring(
    entries: dict[tuple[str, str], str] | None = None,
) -> ModuleType:
    """Build a fake `keyring`-shaped module with a backing dict."""

    class _FakeBackend:
        pass

    backend = _FakeBackend()
    store: dict[tuple[str, str], str] = dict(entries or {})

    def get_keyring() -> _FakeBackend:
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
def fake_secrets_with_sa(tmp_root: Path) -> Iterator[None]:
    """SecretsManager backed by a fake keyring containing the SA JSON."""
    sa_str = json.dumps(_FAKE_SA_JSON)
    fake_kr = _make_fake_keyring(
        {("secops-term:chronicle:default", "service_account_json"): sa_str}
    )
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake_kr))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


@pytest.fixture
def fake_secrets_no_sa(tmp_root: Path) -> Iterator[None]:
    fake_kr = _make_fake_keyring({})
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake_kr))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


def _fake_credentials_factory(token: str = "test-token"):
    """Return a `credentials_factory` callable that yields a fake creds object."""

    class _FakeCreds:
        def __init__(self) -> None:
            self.token = token
            self.valid = True

        def refresh(self, _request: object) -> None:
            self.token = token
            self.valid = True

    def factory(_info: dict[str, object], _scopes: list[str]) -> _FakeCreds:
        return _FakeCreds()

    return factory


# Returns None when [chronicle] block is absent


def test_returns_none_for_empty_config(fake_secrets_no_sa: None) -> None:
    assert factory_mod.build_chronicle_client(cfg_data={}) is None


def test_returns_none_for_no_chronicle_key(fake_secrets_no_sa: None) -> None:
    assert factory_mod.build_chronicle_client(cfg_data={"unrelated": "stuff"}) is None


# Raises on partial / malformed config


def test_raises_when_block_is_not_a_table(
    fake_secrets_no_sa: None,
) -> None:
    with pytest.raises(ChronicleError):
        factory_mod.build_chronicle_client(cfg_data={"chronicle": "not-a-table"})


def test_raises_when_customer_id_missing(
    fake_secrets_no_sa: None,
) -> None:
    with pytest.raises(ChronicleError):
        factory_mod.build_chronicle_client(cfg_data={"chronicle": {"region": "us"}})


def test_raises_when_customer_id_empty(
    fake_secrets_no_sa: None,
) -> None:
    with pytest.raises(ChronicleError):
        factory_mod.build_chronicle_client(
            cfg_data={"chronicle": {"customer_id": "  ", "region": "us"}}
        )


def test_raises_when_region_empty(fake_secrets_no_sa: None) -> None:
    with pytest.raises(ChronicleError):
        factory_mod.build_chronicle_client(
            cfg_data={"chronicle": {"customer_id": "abc", "region": ""}}
        )


def test_raises_when_base_url_not_string(
    fake_secrets_no_sa: None,
) -> None:
    with pytest.raises(ChronicleError):
        factory_mod.build_chronicle_client(
            cfg_data={
                "chronicle": {
                    "customer_id": "abc",
                    "region": "us",
                    "base_url": 42,
                }
            }
        )


# Raises when keyring entry is missing


def test_raises_when_keyring_secret_missing(
    fake_secrets_no_sa: None,
) -> None:
    with pytest.raises(ChronicleError) as exc_info:
        factory_mod.build_chronicle_client(
            cfg_data={"chronicle": {"customer_id": "abc", "region": "us"}}
        )
    assert "service_account_json" in str(exc_info.value)


# Happy path


def test_builds_client_from_config_and_keyring(
    fake_secrets_with_sa: None,
) -> None:
    client = factory_mod.build_chronicle_client(
        cfg_data={
            "chronicle": {
                "customer_id": "abc-123",
                "region": "us",
                "allow_write": False,
            }
        },
        credentials_factory=_fake_credentials_factory(),
    )
    assert client is not None
    assert isinstance(client, ChronicleClient)
    assert client.cfg.customer_id == "abc-123"
    assert client.cfg.region == "us"
    assert client.cfg.allow_write is False
    assert client.base_url == "https://us-chronicle.googleapis.com"


def test_strips_whitespace_in_customer_id_and_region(
    fake_secrets_with_sa: None,
) -> None:
    client = factory_mod.build_chronicle_client(
        cfg_data={
            "chronicle": {
                "customer_id": "  abc-123  ",
                "region": " us ",
            }
        },
        credentials_factory=_fake_credentials_factory(),
    )
    assert client is not None
    assert client.cfg.customer_id == "abc-123"
    assert client.cfg.region == "us"


def test_passes_through_base_url_override(
    fake_secrets_with_sa: None,
) -> None:
    client = factory_mod.build_chronicle_client(
        cfg_data={
            "chronicle": {
                "customer_id": "abc",
                "region": "us",
                "base_url": "https://custom.example.com",
            }
        },
        credentials_factory=_fake_credentials_factory(),
    )
    assert client is not None
    assert client.cfg.base_url == "https://custom.example.com"
    assert client.base_url == "https://custom.example.com"


def test_per_instance_keyring_lookup(tmp_root: Path) -> None:
    """Different `instance=` values look at different keyring rows."""
    sa_str = json.dumps(_FAKE_SA_JSON)
    fake_kr = _make_fake_keyring(
        {
            ("secops-term:chronicle:secondary", "service_account_json"): sa_str,
        }
    )
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake_kr))
    try:
        with pytest.raises(ChronicleError):
            factory_mod.build_chronicle_client(
                cfg_data={"chronicle": {"customer_id": "x", "region": "us"}},
                credentials_factory=_fake_credentials_factory(),
                instance="default",
            )
        client = factory_mod.build_chronicle_client(
            cfg_data={"chronicle": {"customer_id": "x", "region": "us"}},
            credentials_factory=_fake_credentials_factory(),
            instance="secondary",
        )
        assert client is not None
    finally:
        secrets_mod.reset_manager_for_tests()
