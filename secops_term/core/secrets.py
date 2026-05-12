"""Secrets storage: OS keyring primary, Argon2id-Fernet encrypted file fallback.

Per brief v3 §3.5.1:

- One keyring entry per ``(service, key)`` tuple. Service:
  ``secops-term:<provider>:<instance>``.
- Fallback (default-on, opt-out via ``--strict-keyring``): an Argon2id-derived
  Fernet over ``~/.secops-term/secrets.enc``. Argon2id parameters fixed at
  ``memory_cost=65536``, ``time_cost=3``, ``parallelism=4``, salt 16 bytes.
- Passphrase prompted once per session; the derived key is held in a
  ``bytearray`` and zeroized on ``atexit`` and on SIGINT/SIGTERM.
- Every value returned by :meth:`SecretsManager.get_secret` is automatically
  tainted via the redaction registry.
"""

from __future__ import annotations

import atexit
import base64
import contextlib
import getpass
import json
import os
import signal
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import FrameType, ModuleType
from typing import Any

from secops_term.core import paths, redact

_HEADER_MAGIC = b"STSE"
_HEADER_VERSION = 1
_HEADER_FORMAT = ">4sBIBB16s"
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)

_ARGON2_MEMORY_COST = 65536  # 64 MiB
_ARGON2_TIME_COST = 3
_ARGON2_PARALLELISM = 4
_ARGON2_SALT_SIZE = 16
_KEY_SIZE = 32

_SECRETS_FILENAME = "secrets.enc"
_SERVICE_NAME_FORMAT = "secops-term:{provider}:{instance}"


class SecretsError(Exception):
    """Base class for secrets errors."""


class KeyringUnavailable(SecretsError):
    """OS keyring is not usable on this system."""


class StrictKeyringViolation(SecretsError):
    """Strict mode active and keyring init failed."""


class PassphraseRequired(SecretsError):
    """Encrypted-file fallback active but no passphrase provided / mismatch."""


class CorruptSecretsFile(SecretsError):
    """``secrets.enc`` is malformed or fails authentication."""


class SecretBackend(Enum):
    KEYRING = "keyring"
    ENCRYPTED_FILE = "encrypted_file"
    INFISICAL = "infisical"


class PassphraseProvider:
    """Abstraction over ``getpass.getpass`` so tests can inject passphrases."""

    def get(self, *, confirm: bool = False) -> str:
        pw = getpass.getpass("secops-term passphrase: ")
        if confirm:
            again = getpass.getpass("confirm passphrase: ")
            if pw != again:
                raise PassphraseRequired("passphrase confirmation mismatch")
        if not pw:
            raise PassphraseRequired("empty passphrase rejected")
        return pw


class StaticPassphraseProvider(PassphraseProvider):
    """Test helper: always returns a fixed passphrase."""

    def __init__(self, passphrase: str) -> None:
        self._pw = passphrase

    def get(self, *, confirm: bool = False) -> str:
        return self._pw


@dataclass
class SecretsConfig:
    strict_keyring: bool = False
    passphrase_provider: PassphraseProvider | None = None
    keyring_module: ModuleType | None = None
    fernet_factory: Callable[[bytes], Any] | None = None
    argon2_kdf: Callable[..., bytes] | None = field(default=None)


class SecretsManager:
    """Routes secrets to keyring or to the encrypted file fallback."""

    def __init__(self, cfg: SecretsConfig | None = None) -> None:
        self._cfg = cfg if cfg is not None else SecretsConfig()
        self._lock = threading.RLock()
        self._backend: SecretBackend | None = None
        self._key_buf: bytearray | None = None
        self._cached_salt: bytes | None = None
        self._mem_cache: dict[str, str] = {}
        self._cache_loaded = False
        self._zeroize_installed = False

    # Public API

    def initialize(self) -> SecretBackend:
        """Pick a backend. Raises if strict mode and keyring is unavailable.

        Priority order:
        1. Infisical — when ``INFISICAL_TOKEN`` + ``INFISICAL_PROJECT_ID`` env
           vars are present (server / Codespaces deployment).
        2. OS keyring — Windows Credential Manager / macOS Keychain.
        3. Encrypted file fallback — ``~/.secops-term/secrets.enc``.
        """
        with self._lock:
            if self._backend is not None:
                return self._backend
            if os.environ.get("INFISICAL_TOKEN") and os.environ.get("INFISICAL_PROJECT_ID"):
                self._backend = SecretBackend.INFISICAL
                return self._backend
            if self._keyring_works():
                self._backend = SecretBackend.KEYRING
                return self._backend
            if self._cfg.strict_keyring:
                raise StrictKeyringViolation("OS keyring unavailable and --strict-keyring is set")
            self._backend = SecretBackend.ENCRYPTED_FILE
            self._install_zeroize_hooks()
            return self._backend

    def set_secret(self, provider: str, instance: str, field_name: str, value: str) -> None:
        backend = self.initialize()
        if backend is SecretBackend.KEYRING:
            self._keyring_set(provider, instance, field_name, value)
        elif backend is SecretBackend.INFISICAL:
            raise SecretsError(
                "Infisical backend is read-only from this tool. "
                "Create or update secrets in the Infisical dashboard "
                f"(secret name: {_infisical_secret_name(provider, instance, field_name)})."
            )
        else:
            self._file_set(provider, instance, field_name, value)

    def get_secret(self, provider: str, instance: str, field_name: str) -> str | None:
        backend = self.initialize()
        if backend is SecretBackend.KEYRING:
            value = self._keyring_get(provider, instance, field_name)
        elif backend is SecretBackend.INFISICAL:
            value = self._infisical_get(provider, instance, field_name)
        else:
            value = self._file_get(provider, instance, field_name)
        if value is not None:
            redact.taint(value, label=f"{provider}:{instance}:{field_name}")
        return value

    def delete_secret(self, provider: str, instance: str, field_name: str) -> None:
        backend = self.initialize()
        if backend is SecretBackend.KEYRING:
            self._keyring_delete(provider, instance, field_name)
        elif backend is SecretBackend.INFISICAL:
            raise SecretsError("Infisical backend: delete secrets via the Infisical dashboard.")
        else:
            self._file_delete(provider, instance, field_name)

    def shutdown(self) -> None:
        """Zero the key buffer and drop in-memory caches. Idempotent."""
        with self._lock:
            self._zeroize()
            self._mem_cache.clear()
            self._cache_loaded = False
            self._cached_salt = None

    # Keyring backend

    def _keyring(self) -> ModuleType:
        if self._cfg.keyring_module is not None:
            return self._cfg.keyring_module
        import keyring as _kr

        return _kr

    def _keyring_works(self) -> bool:
        try:
            kr = self._keyring()
        except ImportError:
            return False
        try:
            backend = kr.get_keyring()
        except Exception:
            return False
        fqn = f"{type(backend).__module__}.{type(backend).__name__}".lower()
        if "fail" in fqn or "null" in fqn:
            return False
        return True

    @staticmethod
    def _service_name(provider: str, instance: str) -> str:
        return _SERVICE_NAME_FORMAT.format(provider=provider, instance=instance)

    def _keyring_set(self, provider: str, instance: str, field_name: str, value: str) -> None:
        kr = self._keyring()
        kr.set_password(self._service_name(provider, instance), field_name, value)

    def _keyring_get(self, provider: str, instance: str, field_name: str) -> str | None:
        kr = self._keyring()
        result: str | None = kr.get_password(self._service_name(provider, instance), field_name)
        return result

    def _keyring_delete(self, provider: str, instance: str, field_name: str) -> None:
        kr = self._keyring()
        # Idempotent delete: keyring backends raise PasswordDeleteError when the
        # entry is already absent, which is the desired post-condition.
        with contextlib.suppress(Exception):
            kr.delete_password(self._service_name(provider, instance), field_name)

    # Infisical backend

    def _infisical_get(self, provider: str, instance: str, field_name: str) -> str | None:
        """Fetch a secret from Infisical using the REST API.

        Secret naming convention (create these in the Infisical dashboard):
            SECOPS_TERM__{PROVIDER}__{INSTANCE}__{FIELD}
        e.g. ``SECOPS_TERM__CHRONICLE__DEFAULT__SERVICE_ACCOUNT_JSON``

        Environment variables read:
            INFISICAL_TOKEN        — service token (required)
            INFISICAL_PROJECT_ID   — project / workspace ID (required)
            INFISICAL_ENVIRONMENT  — environment slug (default: production)
            INFISICAL_SECRET_PATH  — secret path (default: /)
            INFISICAL_HOST         — self-hosted URL (default: https://app.infisical.com)
        """
        secret_name = _infisical_secret_name(provider, instance, field_name)
        cache_key = f"infisical:{secret_name}"
        with self._lock:
            if cache_key in self._mem_cache:
                return self._mem_cache[cache_key]

        token = os.environ.get("INFISICAL_TOKEN", "")
        project_id = os.environ.get("INFISICAL_PROJECT_ID", "")
        environment = os.environ.get("INFISICAL_ENVIRONMENT", "production")
        secret_path = os.environ.get("INFISICAL_SECRET_PATH", "/")
        host = os.environ.get("INFISICAL_HOST", "https://app.infisical.com").rstrip("/")

        try:
            import httpx

            resp = httpx.get(
                f"{host}/api/v3/secrets/raw/{secret_name}",
                params={
                    "workspaceId": project_id,
                    "environment": environment,
                    "secretPath": secret_path,
                },
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                value: str | None = resp.json().get("secret", {}).get("secretValue")
                if value is not None:
                    with self._lock:
                        self._mem_cache[cache_key] = value
                return value
            return None
        except Exception:
            return None

    # Encrypted-file backend

    def _secrets_path(self) -> Path:
        return paths.safe_join(paths.get_root(), _SECRETS_FILENAME)

    @staticmethod
    def _key(provider: str, instance: str, field_name: str) -> str:
        return f"{provider}:{instance}:{field_name}"

    def _file_set(self, provider: str, instance: str, field_name: str, value: str) -> None:
        with self._lock:
            data, salt = self._load_or_init_unlocked()
            data[self._key(provider, instance, field_name)] = value
            self._save_file_unlocked(data, salt)

    def _file_get(self, provider: str, instance: str, field_name: str) -> str | None:
        with self._lock:
            data, _ = self._load_or_init_unlocked(create_if_missing=False)
            return data.get(self._key(provider, instance, field_name))

    def _file_delete(self, provider: str, instance: str, field_name: str) -> None:
        with self._lock:
            data, salt = self._load_or_init_unlocked(create_if_missing=False)
            if self._key(provider, instance, field_name) in data:
                del data[self._key(provider, instance, field_name)]
                self._save_file_unlocked(data, salt)

    def _load_or_init_unlocked(
        self, *, create_if_missing: bool = True
    ) -> tuple[dict[str, str], bytes]:
        path = self._secrets_path()
        if not path.exists():
            if not create_if_missing:
                return self._mem_cache, b""
            paths.ensure_root_initialized()
            salt = os.urandom(_ARGON2_SALT_SIZE)
            self._cached_salt = salt
            return {}, salt
        if self._cache_loaded and self._cached_salt is not None:
            return self._mem_cache, self._cached_salt
        paths.verify_restrictive_acl(path)
        blob = path.read_bytes()
        if len(blob) < _HEADER_SIZE:
            raise CorruptSecretsFile(f"{path} is too short to contain a header")
        header, ciphertext = blob[:_HEADER_SIZE], blob[_HEADER_SIZE:]
        magic, version, mem_cost, time_cost, parallelism, salt = struct.unpack(
            _HEADER_FORMAT, header
        )
        if magic != _HEADER_MAGIC:
            raise CorruptSecretsFile(f"{path}: bad magic")
        if version != _HEADER_VERSION:
            raise CorruptSecretsFile(f"{path}: unsupported version {version}")
        key = self._derive_fernet_key(salt, mem_cost, time_cost, parallelism)
        plaintext = self._fernet_decrypt(key, ciphertext)
        try:
            data: dict[str, str] = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CorruptSecretsFile(f"{path}: payload not valid JSON") from exc
        self._mem_cache = data
        self._cache_loaded = True
        self._cached_salt = salt
        return self._mem_cache, salt

    def _save_file_unlocked(self, data: dict[str, str], salt: bytes) -> None:
        path = self._secrets_path()
        paths.ensure_root_initialized()
        if not salt:
            salt = os.urandom(_ARGON2_SALT_SIZE)
            self._cached_salt = salt
        key = self._derive_fernet_key(
            salt, _ARGON2_MEMORY_COST, _ARGON2_TIME_COST, _ARGON2_PARALLELISM
        )
        plaintext = json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ciphertext = self._fernet_encrypt(key, plaintext)
        header = struct.pack(
            _HEADER_FORMAT,
            _HEADER_MAGIC,
            _HEADER_VERSION,
            _ARGON2_MEMORY_COST,
            _ARGON2_TIME_COST,
            _ARGON2_PARALLELISM,
            salt,
        )
        tmp = path.with_suffix(path.suffix + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(tmp, flags, 0o600)
        try:
            os.write(fd, header + ciphertext)
        finally:
            os.close(fd)
        paths.apply_restrictive_acl(tmp)
        os.replace(tmp, path)
        paths.apply_restrictive_acl(path)
        self._mem_cache = data
        self._cache_loaded = True
        self._cached_salt = salt

    def _derive_fernet_key(
        self, salt: bytes, mem_cost: int, time_cost: int, parallelism: int
    ) -> bytes:
        if self._key_buf is not None and self._cached_salt == salt:
            return base64.urlsafe_b64encode(bytes(self._key_buf))
        self._zeroize()
        provider = self._cfg.passphrase_provider or PassphraseProvider()
        passphrase = provider.get()
        kdf = self._cfg.argon2_kdf or _argon2id_raw
        try:
            raw = kdf(
                secret=passphrase.encode("utf-8"),
                salt=salt,
                time_cost=time_cost,
                memory_cost=mem_cost,
                parallelism=parallelism,
                hash_len=_KEY_SIZE,
            )
        finally:
            del passphrase
        self._key_buf = bytearray(raw)
        self._cached_salt = salt
        return base64.urlsafe_b64encode(bytes(self._key_buf))

    def _fernet_encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        fernet = self._fernet(key)
        result: bytes = fernet.encrypt(plaintext)
        return result

    def _fernet_decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        from cryptography.fernet import InvalidToken

        fernet = self._fernet(key)
        try:
            result: bytes = fernet.decrypt(ciphertext)
            return result
        except InvalidToken as exc:
            raise CorruptSecretsFile(
                "authentication failed; wrong passphrase or tampered file"
            ) from exc

    def _fernet(self, key: bytes) -> Any:
        if self._cfg.fernet_factory is not None:
            return self._cfg.fernet_factory(key)
        from cryptography.fernet import Fernet

        return Fernet(key)

    # Zeroization

    def _install_zeroize_hooks(self) -> None:
        if self._zeroize_installed:
            return
        atexit.register(self._zeroize)
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                prev = signal.getsignal(sig)
                signal.signal(sig, self._make_signal_handler(prev))
            except (ValueError, OSError):  # pragma: no cover
                # Some environments reject signal.signal in non-main threads.
                pass
        self._zeroize_installed = True

    def _make_signal_handler(self, prev: Any) -> Callable[[int, FrameType | None], None]:
        def handler(signum: int, frame: FrameType | None) -> None:
            self._zeroize()
            if callable(prev):
                prev(signum, frame)

        return handler

    def _zeroize(self) -> None:
        if self._key_buf is None:
            return
        for i in range(len(self._key_buf)):
            self._key_buf[i] = 0
        self._key_buf = None


def _argon2id_raw(
    *,
    secret: bytes,
    salt: bytes,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
    hash_len: int,
) -> bytes:
    """Wrapper around argon2-cffi's low-level ``hash_secret_raw`` (Type.ID)."""
    from argon2.low_level import Type, hash_secret_raw

    raw: bytes = hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
    )
    return raw


def _infisical_secret_name(provider: str, instance: str, field_name: str) -> str:
    """Return the canonical Infisical secret name for a given secops-term key.

    Format: ``SECOPS_TERM__{PROVIDER}__{INSTANCE}__{FIELD}`` (uppercase,
    hyphens and dots replaced with underscores).
    """
    parts = f"{provider}__{instance}__{field_name}"
    return "SECOPS_TERM__" + parts.upper().replace("-", "_").replace(".", "_")


# Module-level singleton

_global: SecretsManager | None = None


def get_manager(cfg: SecretsConfig | None = None) -> SecretsManager:
    """Return the global :class:`SecretsManager`. Pass ``cfg`` only on first call."""
    global _global
    if _global is None:
        _global = SecretsManager(cfg)
    elif cfg is not None:
        raise SecretsError("SecretsManager already initialized; pass cfg only on first call")
    return _global


def reset_manager_for_tests() -> None:
    """Test helper: tear down the module-level singleton."""
    global _global
    if _global is not None:
        _global.shutdown()
    _global = None
