"""Chronicle SecOps OAuth2 token providers.

Two implementations, both satisfying the :class:`ChronicleAuth` Protocol:

- :class:`GoogleServiceAccountAuth` — production: wraps ``google-auth``'s
  ``service_account.Credentials`` and refreshes via the sync ``Request``
  transport in an executor.
- :class:`StaticTokenAuth` — tests: returns a fixed bearer token.

The service-account JSON content lives in the keyring under
``secops-term:chronicle:<instance>`` / ``service_account_json`` (per brief
§3.5.13). Callers fetch it from the secrets manager and hand the dict (or
JSON string) to :class:`GoogleServiceAccountAuth`.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

# Default scope for Chronicle SecOps API. Override via `scopes=` if a
# tenant requires a tighter scope.
DEFAULT_SCOPES: tuple[str, ...] = ("https://www.googleapis.com/auth/cloud-platform",)


class ChronicleAuthError(Exception):
    """Base class for Chronicle auth errors."""


class ChronicleAuth(Protocol):
    """A bearer-token provider for the Chronicle client."""

    async def get_token(self) -> str: ...


class StaticTokenAuth:
    """Tests-only: returns a fixed token. Never expires."""

    def __init__(self, token: str) -> None:
        if not token:
            raise ChronicleAuthError("StaticTokenAuth: empty token")
        self._token = token

    async def get_token(self) -> str:
        return self._token


class GoogleServiceAccountAuth:
    """Service-account-backed access-token source.

    Refresh is run in the default executor so the caller's event loop
    stays responsive — ``google-auth-requests`` is a sync transport and
    blocks during the network call.

    For tests, pass ``credentials_factory=`` to bypass the real
    ``google.oauth2.service_account.Credentials.from_service_account_info``.
    """

    def __init__(
        self,
        service_account_info: dict[str, Any] | str,
        *,
        scopes: Sequence[str] = DEFAULT_SCOPES,
        credentials_factory: (Callable[[dict[str, Any], list[str]], Any] | None) = None,
    ) -> None:
        if isinstance(service_account_info, str):
            try:
                info = json.loads(service_account_info)
            except json.JSONDecodeError as exc:
                raise ChronicleAuthError(
                    f"service_account_info is not valid JSON: {exc.msg}"
                ) from exc
        else:
            info = dict(service_account_info)
        if not isinstance(info, dict):
            raise ChronicleAuthError("service_account_info must decode to a JSON object")
        self._info = info
        self._scopes = tuple(scopes)
        self._credentials_factory = credentials_factory
        self._creds: Any = None

    @property
    def client_email(self) -> str | None:
        """The ``client_email`` field from the SA JSON, for diagnostics."""
        v = self._info.get("client_email")
        return v if isinstance(v, str) else None

    async def get_token(self) -> str:
        if self._creds is None:
            self._creds = self._build_credentials()
        if not self._is_valid():
            await asyncio.get_running_loop().run_in_executor(None, self._refresh_blocking)
        token = getattr(self._creds, "token", None)
        if not isinstance(token, str) or not token:
            raise ChronicleAuthError("no token after refresh")
        return token

    def _is_valid(self) -> bool:
        return bool(getattr(self._creds, "valid", False)) and bool(
            getattr(self._creds, "token", None)
        )

    def _build_credentials(self) -> Any:
        if self._credentials_factory is not None:
            return self._credentials_factory(self._info, list(self._scopes))
        try:
            from google.oauth2 import service_account
        except ImportError as exc:
            raise ChronicleAuthError(
                "google-auth not installed; add `google-auth>=2.0` to your deps"
            ) from exc
        try:
            return service_account.Credentials.from_service_account_info(  # type: ignore[no-untyped-call]
                self._info, scopes=list(self._scopes)
            )
        except Exception as exc:
            raise ChronicleAuthError(
                f"could not build credentials: {type(exc).__name__}: {exc}"
            ) from exc

    def _refresh_blocking(self) -> None:
        try:
            from google.auth.transport.requests import Request
        except ImportError as exc:
            raise ChronicleAuthError(
                "google-auth-requests not available; "
                "install `google-auth` (it ships with the requests transport)"
            ) from exc
        try:
            self._creds.refresh(Request())
        except Exception as exc:
            raise ChronicleAuthError(f"token refresh failed: {type(exc).__name__}: {exc}") from exc


__all__ = [
    "DEFAULT_SCOPES",
    "ChronicleAuth",
    "ChronicleAuthError",
    "GoogleServiceAccountAuth",
    "StaticTokenAuth",
]
