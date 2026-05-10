"""Alert ingest pipeline — combines Chronicle / V1 / DS, dedupes, groups."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import httpx
import pytest
import respx

from secops_term.alerts import ingest as ingest_mod
from secops_term.core import secrets as secrets_mod


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


_FAKE_SA_JSON = json.dumps(
    {
        "type": "service_account",
        "client_email": "sa@example.iam.gserviceaccount.com",
        "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
    }
)


def _fake_keyring(entries: dict[tuple[str, str], str]) -> ModuleType:
    class _Backend:
        pass

    backend = _Backend()
    store: dict[tuple[str, str], str] = dict(entries)

    def get_keyring() -> _Backend:
        return backend

    def set_password(s: str, k: str, v: str) -> None:
        store[(s, k)] = v

    def get_password(s: str, k: str) -> str | None:
        return store.get((s, k))

    def delete_password(s: str, k: str) -> None:
        store.pop((s, k), None)

    mod = ModuleType("fake_keyring")
    mod.get_keyring = get_keyring  # type: ignore[attr-defined]
    mod.set_password = set_password  # type: ignore[attr-defined]
    mod.get_password = get_password  # type: ignore[attr-defined]
    mod.delete_password = delete_password  # type: ignore[attr-defined]
    return mod


@pytest.fixture
def fake_secrets_all_three(tmp_root: Path) -> Iterator[None]:
    fake_kr = _fake_keyring(
        {
            ("secops-term:chronicle:default", "service_account_json"): _FAKE_SA_JSON,
            ("secops-term:vision_one:default", "api_token"): "v1-token",
            ("secops-term:deep_security:default", "api_key"): "ds-key",
        }
    )
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=fake_kr))
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


def _fake_credentials_factory():
    class _FakeCreds:
        def __init__(self) -> None:
            self.token = "test-token"
            self.valid = True

        def refresh(self, _r: object) -> None:
            self.token = "test-token"
            self.valid = True

    return lambda _info, _scopes: _FakeCreds()


@pytest.fixture
def patch_chronicle_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the Chronicle factory so it uses fake google-auth credentials."""
    from secops_term.chronicle import factory as chronicle_factory

    real = chronicle_factory.build_chronicle_client

    def patched(**kwargs):
        kwargs.setdefault("credentials_factory", _fake_credentials_factory())
        return real(**kwargs)

    monkeypatch.setattr(
        ingest_mod.chronicle_factory,
        "build_chronicle_client",
        patched,
    )


# ingest_all — no sources configured


async def test_ingest_no_sources_returns_empty(tmp_root: Path) -> None:
    result = await ingest_mod.ingest_all(cfg_data={})
    assert result.per_source == []
    assert result.alerts == []
    assert result.groups == []


# ingest_all — one source per call


async def test_ingest_chronicle_only(
    fake_secrets_all_three: None,
    patch_chronicle_creds: None,
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://us-chronicle.googleapis.com/v1alpha/abc:listAlerts").mock(
        return_value=httpx.Response(
            200,
            json={
                "alerts": [
                    {
                        "id": "chr-1",
                        "ruleName": "Suspicious PowerShell",
                        "severity": "high",
                        "detectionTime": "2026-06-01T12:00:00Z",
                    }
                ]
            },
        )
    )
    cfg = {"chronicle": {"customer_id": "abc", "region": "us"}}
    result = await ingest_mod.ingest_all(cfg_data=cfg)
    assert len(result.per_source) == 1
    assert result.per_source[0].source == "chronicle"
    assert result.per_source[0].ok is True
    assert len(result.alerts) == 1
    assert result.alerts[0].source == "chronicle"
    assert result.alerts[0].title == "Suspicious PowerShell"


async def test_ingest_vision_one_only(
    fake_secrets_all_three: None,
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": "v1-1",
                        "model": "Suspicious Login",
                        "severity": "medium",
                        "createdDateTime": "2026-06-01T08:00:00Z",
                    }
                ],
                "totalCount": 1,
            },
        )
    )
    cfg = {"vision_one": {}}
    result = await ingest_mod.ingest_all(cfg_data=cfg)
    assert len(result.per_source) == 1
    assert result.per_source[0].source == "vision_one"
    assert len(result.alerts) == 1


async def test_ingest_deep_security_only(
    fake_secrets_all_three: None,
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/alerts").mock(
        return_value=httpx.Response(
            200,
            json={
                "alerts": [
                    {
                        "ID": 1,
                        "name": "AM Alert",
                        "severity": "high",
                        "alertedTime": "2026-06-01T01:00:00Z",
                    }
                ]
            },
        )
    )
    cfg = {"deep_security": {}}
    result = await ingest_mod.ingest_all(cfg_data=cfg)
    assert len(result.per_source) == 1
    assert result.per_source[0].source == "deep_security"
    assert len(result.alerts) == 1


# ingest_all — all three


async def test_ingest_all_three_sources(
    fake_secrets_all_three: None,
    patch_chronicle_creds: None,
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://us-chronicle.googleapis.com/v1alpha/abc:listAlerts").mock(
        return_value=httpx.Response(200, json={"alerts": [{"id": "chr-1", "severity": "high"}]})
    )
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(200, json={"items": [{"id": "v1-1", "severity": "high"}]})
    )
    respx_router.get("https://app.deepsecurity.trendmicro.com/api/alerts").mock(
        return_value=httpx.Response(
            200, json={"alerts": [{"ID": 1, "name": "x", "severity": "high"}]}
        )
    )
    cfg = {
        "chronicle": {"customer_id": "abc", "region": "us"},
        "vision_one": {},
        "deep_security": {},
    }
    result = await ingest_mod.ingest_all(cfg_data=cfg)
    assert {s.source for s in result.per_source} == {
        "chronicle",
        "vision_one",
        "deep_security",
    }
    assert len(result.alerts) == 3


# Failure handling


async def test_ingest_one_source_failure_does_not_block_others(
    fake_secrets_all_three: None,
    patch_chronicle_creds: None,
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://us-chronicle.googleapis.com/v1alpha/abc:listAlerts").mock(
        return_value=httpx.Response(500, text="chronicle down")
    )
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(200, json={"items": [{"id": "v1-1"}]})
    )
    cfg = {
        "chronicle": {"customer_id": "abc", "region": "us"},
        "vision_one": {},
    }
    result = await ingest_mod.ingest_all(cfg_data=cfg)
    chronicle_src = next(s for s in result.per_source if s.source == "chronicle")
    assert chronicle_src.ok is False
    v1_src = next(s for s in result.per_source if s.source == "vision_one")
    assert v1_src.ok is True
    # The successful source's alerts still flow through.
    assert len(result.alerts) == 1
    assert result.alerts[0].source == "vision_one"


async def test_ingest_passes_since_to_each_source(
    fake_secrets_all_three: None,
    patch_chronicle_creds: None,
    respx_router: respx.Router,
) -> None:
    chr_route = respx_router.get("https://us-chronicle.googleapis.com/v1alpha/abc:listAlerts").mock(
        return_value=httpx.Response(200, json={"alerts": []})
    )
    v1_route = respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    ds_route = respx_router.get("https://app.deepsecurity.trendmicro.com/api/alerts").mock(
        return_value=httpx.Response(200, json={"alerts": []})
    )
    cfg = {
        "chronicle": {"customer_id": "abc", "region": "us"},
        "vision_one": {},
        "deep_security": {},
    }
    since = datetime(2026, 1, 1, tzinfo=UTC)
    await ingest_mod.ingest_all(cfg_data=cfg, since=since)
    assert "startTime=2026-01-01T00" in str(chr_route.calls[0].request.url)
    assert "startDateTime=2026-01-01T00" in str(v1_route.calls[0].request.url)
    assert "since=2026-01-01T00" in str(ds_route.calls[0].request.url)


# Dedup at the ingest layer


async def test_ingest_dedupes_within_one_source(
    fake_secrets_all_three: None,
    respx_router: respx.Router,
) -> None:
    """Same alert id from V1 should appear only once after dedup."""
    respx_router.get("https://api.xdr.trendmicro.com/v3.0/workbench/alerts").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {"id": "v1-dup", "severity": "high"},
                    {"id": "v1-dup", "severity": "high"},
                    {"id": "v1-uniq", "severity": "high"},
                ]
            },
        )
    )
    cfg = {"vision_one": {}}
    result = await ingest_mod.ingest_all(cfg_data=cfg)
    assert len(result.alerts) == 2
    ids = {a.id for a in result.alerts}
    assert ids == {"v1-dup", "v1-uniq"}
