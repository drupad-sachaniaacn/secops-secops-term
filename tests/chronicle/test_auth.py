"""Chronicle auth — both StaticTokenAuth and GoogleServiceAccountAuth (mocked)."""

from __future__ import annotations

import pytest

from secops_term.chronicle import auth as auth_mod

# StaticTokenAuth


async def test_static_token_returns_fixed_string() -> None:
    a = auth_mod.StaticTokenAuth("test-token-abc")
    assert await a.get_token() == "test-token-abc"


def test_static_token_rejects_empty() -> None:
    with pytest.raises(auth_mod.ChronicleAuthError):
        auth_mod.StaticTokenAuth("")


# GoogleServiceAccountAuth (with credentials_factory injection)


def _fake_creds_factory(tokens: list[str]):
    """Build a fake credentials object that emits ``tokens[i]`` on each refresh."""
    state = {"i": 0, "valid": False}

    class _FakeCreds:
        def __init__(self) -> None:
            self.token: str | None = None

        @property
        def valid(self) -> bool:
            return state["valid"]

        def refresh(self, _request: object) -> None:
            self.token = tokens[state["i"]]
            state["i"] = min(state["i"] + 1, len(tokens) - 1)
            state["valid"] = True

    creds = _FakeCreds()

    def factory(info: dict[str, object], scopes: list[str]) -> _FakeCreds:
        # `info` and `scopes` are exercised by the real builder; the fake just stashes them.
        creds._info = info  # type: ignore[attr-defined]
        creds._scopes = scopes  # type: ignore[attr-defined]
        return creds

    return factory, creds


async def test_google_auth_refreshes_on_first_call() -> None:
    factory, creds = _fake_creds_factory(["first-token"])
    a = auth_mod.GoogleServiceAccountAuth(
        {"type": "service_account", "client_email": "x@y.com"},
        credentials_factory=factory,
    )
    assert creds.token is None
    token = await a.get_token()
    assert token == "first-token"
    assert creds.token == "first-token"


async def test_google_auth_returns_cached_token_when_valid() -> None:
    factory, _creds = _fake_creds_factory(["first", "second"])
    a = auth_mod.GoogleServiceAccountAuth(
        {"type": "service_account"},
        credentials_factory=factory,
    )
    t1 = await a.get_token()
    t2 = await a.get_token()
    assert t1 == "first"
    assert t2 == "first"  # not refreshed again


async def test_google_auth_accepts_json_string() -> None:
    factory, _ = _fake_creds_factory(["t"])
    sa_str = '{"type": "service_account", "client_email": "z@y.com"}'
    a = auth_mod.GoogleServiceAccountAuth(sa_str, credentials_factory=factory)
    assert await a.get_token() == "t"


def test_google_auth_rejects_malformed_json() -> None:
    with pytest.raises(auth_mod.ChronicleAuthError):
        auth_mod.GoogleServiceAccountAuth("not-json{")


def test_google_auth_rejects_non_object_json() -> None:
    with pytest.raises(auth_mod.ChronicleAuthError):
        auth_mod.GoogleServiceAccountAuth('"just-a-string"')


def test_client_email_property() -> None:
    factory, _ = _fake_creds_factory(["t"])
    a = auth_mod.GoogleServiceAccountAuth(
        {"client_email": "robot@project.iam.gserviceaccount.com"},
        credentials_factory=factory,
    )
    assert a.client_email == "robot@project.iam.gserviceaccount.com"


def test_client_email_missing_returns_none() -> None:
    factory, _ = _fake_creds_factory(["t"])
    a = auth_mod.GoogleServiceAccountAuth({}, credentials_factory=factory)
    assert a.client_email is None


async def test_google_auth_raises_on_missing_token_after_refresh() -> None:
    """If the credentials object's token stays None after refresh, raise."""

    class _BadCreds:
        token = None
        valid = False

        def refresh(self, _req: object) -> None:
            # Never sets self.token.
            self.valid = True

    a = auth_mod.GoogleServiceAccountAuth(
        {},
        credentials_factory=lambda *_: _BadCreds(),
    )
    with pytest.raises(auth_mod.ChronicleAuthError):
        await a.get_token()
