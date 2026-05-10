"""CLI: ``hunt enqueue`` / ``hunt run`` / ``hunt status`` + chronicle in config test."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import httpx
import pytest
import respx
from typer.testing import CliRunner

from secops_term import cli as cli_mod
from secops_term.chronicle import factory as chronicle_factory
from secops_term.cli import app
from secops_term.core import config_io
from secops_term.core import db as core_db
from secops_term.core import secrets as secrets_mod
from secops_term.intel import store as store_mod
from secops_term.intel.providers.base import IntelRecord

runner = CliRunner()

_SA_JSON = json.dumps(
    {
        "type": "service_account",
        "client_email": "robot@project.iam.gserviceaccount.com",
        "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
    }
)


# Fixtures


def _make_fake_keyring() -> ModuleType:
    class _FakeBackend:
        pass

    backend = _FakeBackend()
    store: dict[tuple[str, str], str] = {
        ("secops-term:chronicle:default", "service_account_json"): _SA_JSON,
    }

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
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


@pytest.fixture
def configured_chronicle(
    tmp_root: Path,
    migrated_db: core_db.Database,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Wire up a fully-configured Chronicle: config.toml + keyring + factory injection."""
    secrets_mod.reset_manager_for_tests()
    secrets_mod.get_manager(secrets_mod.SecretsConfig(keyring_module=_make_fake_keyring()))
    config_io.save_config(
        {
            "chronicle": {
                "customer_id": "abc-123",
                "region": "us",
            }
        }
    )
    # Patch the factory so it uses our fake credentials_factory.
    real_build = chronicle_factory.build_chronicle_client

    def patched_build(**kwargs: object):
        kwargs.setdefault("credentials_factory", _fake_credentials_factory())
        return real_build(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        cli_mod.chronicle_factory,
        "build_chronicle_client",
        patched_build,
    )
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


def _seed_ioc(store: store_mod.IOCStore, *, type_: str, value: str) -> int:
    ioc_id, _ = store.upsert(
        IntelRecord(
            source="test:default",
            type=type_,
            value=value,
            fetched_at=datetime.now(UTC),
        )
    )
    return ioc_id


# hunt enqueue


def test_hunt_enqueue_inserts_queued_job(tmp_root: Path, migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="ipv4", value="8.8.8.8")
    result = runner.invoke(app, ["hunt", "enqueue", str(ioc_id)])
    assert result.exit_code == 0
    assert "Enqueued job" in result.stdout
    s = store_mod.get_default_store()
    try:
        jobs = s.recent_jobs(platform="chronicle")
        assert len(jobs) == 1
        assert jobs[0].status == store_mod.JOB_QUEUED
        assert jobs[0].ioc_id == ioc_id
    finally:
        s.database.close()


def test_hunt_enqueue_unknown_ioc(tmp_root: Path, migrated_db: core_db.Database) -> None:
    result = runner.invoke(app, ["hunt", "enqueue", "9999"])
    assert result.exit_code == 1
    assert "No IOC" in result.stdout


def test_hunt_enqueue_custom_platform(tmp_root: Path, migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="ipv4", value="1.1.1.1")
    result = runner.invoke(app, ["hunt", "enqueue", str(ioc_id), "--platform", "vision_one"])
    assert result.exit_code == 0
    s = store_mod.get_default_store()
    try:
        jobs = s.recent_jobs(platform="vision_one")
        assert len(jobs) == 1
    finally:
        s.database.close()


# hunt status


def test_hunt_status_no_jobs(tmp_root: Path, migrated_db: core_db.Database) -> None:
    result = runner.invoke(app, ["hunt", "status"])
    assert result.exit_code == 0
    assert "(no retro-hunt jobs)" in result.stdout


def test_hunt_status_lists_jobs(tmp_root: Path, migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="ipv4", value="8.8.8.8")
    store.enqueue_retro_hunt(ioc_id, "chronicle")
    result = runner.invoke(app, ["hunt", "status"])
    assert result.exit_code == 0
    assert "8.8.8.8" in result.stdout
    assert "queued" in result.stdout


def test_hunt_status_filters_by_status(tmp_root: Path, migrated_db: core_db.Database) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="ipv4", value="8.8.8.8")
    store.enqueue_retro_hunt(ioc_id, "chronicle")  # queued
    done_id = store.enqueue_retro_hunt(ioc_id, "chronicle")
    store.complete_job(done_id, hits=5, query="x")
    result = runner.invoke(app, ["hunt", "status", "--status", "done"])
    assert result.exit_code == 0
    # The status column should show "done" for the (only) listed row.
    # The "queued" status of the other job must not appear in the rendered
    # table body — it would if the filter weren't applied.
    assert "done" in result.stdout
    assert "queued" not in result.stdout


def test_hunt_status_invalid_status(tmp_root: Path, migrated_db: core_db.Database) -> None:
    result = runner.invoke(app, ["hunt", "status", "--status", "bogus"])
    assert result.exit_code == 1
    assert "unknown status" in result.stdout


# hunt run — Chronicle wired


def test_hunt_run_unconfigured(tmp_root: Path, migrated_db: core_db.Database) -> None:
    result = runner.invoke(app, ["hunt", "run"])
    assert result.exit_code == 1
    assert "Chronicle not configured" in result.stdout


def test_hunt_run_drains_to_done(
    configured_chronicle: None,
    migrated_db: core_db.Database,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/abc-123:udmSearch").mock(
        return_value=httpx.Response(200, json={"events": [{"x": 1}, {"x": 2}], "total_events": 2})
    )
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="ipv4", value="8.8.8.8")
    store.enqueue_retro_hunt(ioc_id, "chronicle")
    result = runner.invoke(app, ["hunt", "run"])
    assert result.exit_code == 0
    assert "Drained" in result.stdout
    assert "1 succeeded" in result.stdout
    s = store_mod.get_default_store()
    try:
        jobs = s.recent_jobs()
        assert jobs[0].status == store_mod.JOB_DONE
        assert jobs[0].hits == 2
    finally:
        s.database.close()


def test_hunt_run_returns_nonzero_on_failure(
    configured_chronicle: None,
    migrated_db: core_db.Database,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/abc-123:udmSearch").mock(
        return_value=httpx.Response(401, text="bad creds")
    )
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="ipv4", value="8.8.8.8")
    store.enqueue_retro_hunt(ioc_id, "chronicle")
    result = runner.invoke(app, ["hunt", "run"])
    assert result.exit_code == 1
    assert "1 failed" in result.stdout


def test_hunt_run_no_jobs(
    configured_chronicle: None,
    migrated_db: core_db.Database,
    respx_router: respx.Router,
) -> None:
    result = runner.invoke(app, ["hunt", "run"])
    assert result.exit_code == 0
    assert "Drained 0" in result.stdout


# config test chronicle


def test_config_test_chronicle_unconfigured(tmp_root: Path) -> None:
    result = runner.invoke(app, ["config", "test", "chronicle"])
    assert result.exit_code == 1
    assert "Chronicle not configured" in result.stdout


def test_config_test_chronicle_succeeds(
    configured_chronicle: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/abc-123:udmSearch").mock(
        return_value=httpx.Response(200, json={"events": []})
    )
    result = runner.invoke(app, ["config", "test", "chronicle"])
    assert result.exit_code == 0
    assert "OK" in result.stdout
    assert "abc-123" in result.stdout


def test_config_test_chronicle_fails_on_401(
    configured_chronicle: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/abc-123:udmSearch").mock(
        return_value=httpx.Response(401)
    )
    result = runner.invoke(app, ["config", "test", "chronicle"])
    assert result.exit_code == 1
    assert "FAIL" in result.stdout


# config test-all includes Chronicle


def test_config_test_all_includes_chronicle(
    configured_chronicle: None,
    respx_router: respx.Router,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/abc-123:udmSearch").mock(
        return_value=httpx.Response(200, json={"events": []})
    )
    result = runner.invoke(app, ["config", "test-all"])
    assert result.exit_code == 0
    assert "chronicle" in result.stdout
