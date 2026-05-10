"""SecretsManager: keyring backend + Argon2id-Fernet encrypted-file fallback."""

from __future__ import annotations

import os
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from secops_term.core import paths, secrets


class _FakeKeyringBackend:
    """Stub keyring backend; type name does not contain 'fail' or 'null'."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}


def _make_fake_keyring_module() -> ModuleType:
    backend = _FakeKeyringBackend()

    def get_keyring() -> _FakeKeyringBackend:
        return backend

    def set_password(service: str, key: str, value: str) -> None:
        backend.store[(service, key)] = value

    def get_password(service: str, key: str) -> str | None:
        return backend.store.get((service, key))

    def delete_password(service: str, key: str) -> None:
        backend.store.pop((service, key), None)

    mod = ModuleType("fake_keyring")
    mod.get_keyring = get_keyring  # type: ignore[attr-defined]
    mod.set_password = set_password  # type: ignore[attr-defined]
    mod.get_password = get_password  # type: ignore[attr-defined]
    mod.delete_password = delete_password  # type: ignore[attr-defined]
    return mod


def _make_failing_keyring_module() -> ModuleType:
    def get_keyring() -> Any:
        raise RuntimeError("simulated keyring failure")

    mod = ModuleType("failing_keyring")
    mod.get_keyring = get_keyring  # type: ignore[attr-defined]
    return mod


# Keyring backend


def test_keyring_backend_set_get_delete(tmp_root: Path) -> None:
    cfg = secrets.SecretsConfig(keyring_module=_make_fake_keyring_module())
    mgr = secrets.SecretsManager(cfg)
    assert mgr.initialize() is secrets.SecretBackend.KEYRING

    mgr.set_secret("vt", "default", "api_key", "sk-supersecret-AAAA")
    assert mgr.get_secret("vt", "default", "api_key") == "sk-supersecret-AAAA"
    mgr.delete_secret("vt", "default", "api_key")
    assert mgr.get_secret("vt", "default", "api_key") is None


def test_keyring_get_taints_returned_value(tmp_root: Path) -> None:
    from secops_term.core import redact

    cfg = secrets.SecretsConfig(keyring_module=_make_fake_keyring_module())
    mgr = secrets.SecretsManager(cfg)
    mgr.set_secret("vt", "default", "api_key", "sk-supersecret-BBBB")
    mgr.get_secret("vt", "default", "api_key")
    out = redact.redact("the value was sk-supersecret-BBBB leaked")
    assert "sk-supersecret" not in out
    assert "<redacted:vt:default:api_key>" in out


# Strict mode


def test_strict_mode_refuses_fallback(tmp_root: Path) -> None:
    cfg = secrets.SecretsConfig(
        strict_keyring=True,
        keyring_module=_make_failing_keyring_module(),
    )
    mgr = secrets.SecretsManager(cfg)
    with pytest.raises(secrets.StrictKeyringViolation):
        mgr.initialize()


# Encrypted-file fallback


_DEFAULT_TEST_PASSPHRASE = "correct horse battery staple"


def _file_fallback_manager(passphrase: str | None = None) -> secrets.SecretsManager:
    cfg = secrets.SecretsConfig(
        keyring_module=_make_failing_keyring_module(),
        passphrase_provider=secrets.StaticPassphraseProvider(
            passphrase or _DEFAULT_TEST_PASSPHRASE
        ),
    )
    return secrets.SecretsManager(cfg)


def test_encrypted_file_set_get_delete(tmp_root: Path) -> None:
    mgr = _file_fallback_manager()
    assert mgr.initialize() is secrets.SecretBackend.ENCRYPTED_FILE

    mgr.set_secret("chronicle", "primary", "service_account_json", '{"k":"v"}')
    assert mgr.get_secret("chronicle", "primary", "service_account_json") == '{"k":"v"}'

    secrets_file = tmp_root / "secrets.enc"
    assert secrets_file.exists()
    if os.name != "nt":
        mode = secrets_file.stat().st_mode & 0o777
        assert mode == 0o600

    mgr.delete_secret("chronicle", "primary", "service_account_json")
    assert mgr.get_secret("chronicle", "primary", "service_account_json") is None


def test_encrypted_file_persists_across_managers(tmp_root: Path) -> None:
    pw = "another reasonable passphrase"
    m1 = _file_fallback_manager(pw)
    m1.set_secret("vt", "default", "api_key", "sk-AAAA-1234")
    m1.shutdown()

    m2 = _file_fallback_manager(pw)
    assert m2.get_secret("vt", "default", "api_key") == "sk-AAAA-1234"


def test_encrypted_file_wrong_passphrase_fails(tmp_root: Path) -> None:
    m1 = _file_fallback_manager("right passphrase")
    m1.set_secret("vt", "default", "api_key", "sk-AAAA-1234")
    m1.shutdown()

    m2 = _file_fallback_manager("WRONG passphrase")
    with pytest.raises(secrets.CorruptSecretsFile):
        m2.get_secret("vt", "default", "api_key")


def test_encrypted_file_corrupted_payload_fails(tmp_root: Path) -> None:
    m1 = _file_fallback_manager("pw")
    m1.set_secret("vt", "default", "api_key", "sk-AAAA-1234")
    m1.shutdown()

    secrets_file = tmp_root / "secrets.enc"
    blob = bytearray(secrets_file.read_bytes())
    # Flip a byte in the ciphertext (after the 27-byte header).
    blob[40] ^= 0xFF
    secrets_file.write_bytes(bytes(blob))

    m2 = _file_fallback_manager("pw")
    with pytest.raises(secrets.CorruptSecretsFile):
        m2.get_secret("vt", "default", "api_key")


def test_encrypted_file_bad_magic_fails(tmp_root: Path) -> None:
    secrets_file = tmp_root / "secrets.enc"
    secrets_file.write_bytes(b"NOTSTSE" + b"\x00" * 100)
    paths.apply_restrictive_acl(secrets_file)

    m = _file_fallback_manager("pw")
    with pytest.raises(secrets.CorruptSecretsFile):
        m.get_secret("vt", "default", "api_key")


def test_passphrase_confirmation_mismatch_raises() -> None:
    class MismatchProvider(secrets.PassphraseProvider):
        def __init__(self) -> None:
            self._calls = 0

        def get(self, *, confirm: bool = False) -> str:
            self._calls += 1
            return f"pw{self._calls}" if confirm else "pw"

    # Direct call to confirm-mode raises on mismatch.
    p = secrets.PassphraseProvider()

    class _Fake:
        def __init__(self) -> None:
            self.values = ["one", "two"]
            self.i = 0

        def __call__(self, prompt: str = "") -> str:
            v = self.values[self.i]
            self.i += 1
            return v

    import getpass as _gp

    fake = _Fake()
    real = _gp.getpass
    _gp.getpass = fake  # type: ignore[assignment]
    try:
        with pytest.raises(secrets.PassphraseRequired):
            p.get(confirm=True)
    finally:
        _gp.getpass = real  # type: ignore[assignment]


def test_passphrase_empty_raises() -> None:
    p = secrets.PassphraseProvider()

    import getpass as _gp

    real = _gp.getpass
    _gp.getpass = lambda prompt="": ""  # type: ignore[assignment]
    try:
        with pytest.raises(secrets.PassphraseRequired):
            p.get()
    finally:
        _gp.getpass = real  # type: ignore[assignment]


# Service name format


def test_service_name_format() -> None:
    name = secrets.SecretsManager._service_name("notifications.slack", "soc-alerts")
    assert name == "secops-term:notifications.slack:soc-alerts"


# Singleton


def test_singleton_get_manager_idempotent(tmp_root: Path) -> None:
    cfg = secrets.SecretsConfig(keyring_module=_make_fake_keyring_module())
    m1 = secrets.get_manager(cfg)
    m2 = secrets.get_manager()
    assert m1 is m2
    with pytest.raises(secrets.SecretsError):
        secrets.get_manager(cfg)  # cfg passed after first call


# Sanity reference (silence unused import warning if SimpleNamespace removed later)
_ = SimpleNamespace
