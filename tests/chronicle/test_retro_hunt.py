"""Chronicle retro-hunt: UDM query builder + drain worker."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
import respx

from secops_term.chronicle import auth as auth_mod
from secops_term.chronicle import client as client_mod
from secops_term.chronicle import retro_hunt
from secops_term.core import db as core_db
from secops_term.intel import store as store_mod
from secops_term.intel.providers.base import IntelRecord

# Fixtures


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _client(*, customer_id: str = "cust-1") -> client_mod.ChronicleClient:
    cfg = client_mod.ChronicleConfig(customer_id=customer_id, region="us")
    return client_mod.ChronicleClient(cfg, auth=auth_mod.StaticTokenAuth("t"))


def _seed_ioc(
    store: store_mod.IOCStore,
    *,
    type_: str,
    value: str,
) -> int:
    ioc_id, _ = store.upsert(
        IntelRecord(
            source="test:default",
            type=type_,
            value=value,
            fetched_at=datetime.now(UTC),
        )
    )
    return ioc_id


# build_udm_query


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected_substrings"),
    [
        (
            "ipv4",
            "8.8.8.8",
            ['principal.ip = "8.8.8.8"', "target.ip", "src.ip", "dst.ip"],
        ),
        (
            "ipv6",
            "2001:db8::1",
            ['principal.ip = "2001:db8::1"', "target.ip"],
        ),
        (
            "domain",
            "evil.example.com",
            [
                'network.dns.questions.name = "evil.example.com"',
                'principal.domain.name = "evil.example.com"',
                'target.domain.name = "evil.example.com"',
            ],
        ),
        (
            "url",
            "https://evil.example.com/c2",
            [
                'network.http.referral_url = "https://evil.example.com/c2"',
                'target.url = "https://evil.example.com/c2"',
            ],
        ),
        ("sha256", "a" * 64, [f'target.file.sha256 = "{"a" * 64}"']),
        ("sha1", "b" * 40, [f'target.file.sha1 = "{"b" * 40}"']),
        ("md5", "c" * 32, [f'target.file.md5 = "{"c" * 32}"']),
        (
            "email",
            "attacker@evil.example.com",
            [
                'network.email.from = "attacker@evil.example.com"',
                'network.email.to = "attacker@evil.example.com"',
            ],
        ),
        (
            "cve",
            "CVE-2024-1234",
            ['vulnerability.about.vulnerability.cve_id = "CVE-2024-1234"'],
        ),
    ],
)
def test_build_udm_query_for_each_type(
    ioc_type: str, value: str, expected_substrings: list[str]
) -> None:
    query = retro_hunt.build_udm_query(ioc_type, value)
    for sub in expected_substrings:
        assert sub in query


def test_build_udm_query_rejects_unsupported_type() -> None:
    with pytest.raises(retro_hunt.UnsupportedIOCType):
        retro_hunt.build_udm_query("not-a-type", "anything")


def test_build_udm_query_escapes_quotes() -> None:
    """Defence in depth: a value with a quote shouldn't break the query syntactically."""
    query = retro_hunt.build_udm_query("domain", 'evil".com')
    # The literal `"` in the value gets escaped as `\"`. Each expression
    # therefore has three quotes (open, escaped-literal, close). Three
    # expressions x three quotes = nine.
    assert r"\"" in query
    assert query.count('"') == 9


def test_build_udm_query_escapes_backslashes() -> None:
    query = retro_hunt.build_udm_query("domain", r"evil\name")
    # Single backslash → escaped pair.
    assert r"evil\\name" in query


# Worker — drain


async def test_worker_drains_one_job_to_done(
    respx_router: respx.Router,
    migrated_db: core_db.Database,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-1:udmSearch").mock(
        return_value=httpx.Response(
            200,
            json={
                "events": [{"x": 1}, {"x": 2}, {"x": 3}],
                "total_events": 3,
            },
        )
    )
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="ipv4", value="8.8.8.8")
    job_id = store.enqueue_retro_hunt(ioc_id, retro_hunt.CHRONICLE_PLATFORM)
    worker = retro_hunt.RetroHuntWorker(_client(), store)

    result = await worker.run_once()
    assert result.drained == 1
    assert result.succeeded == 1
    assert result.failed == 0
    assert result.skipped == 0
    job = store.get_job(job_id)
    assert job is not None
    assert job.status == store_mod.JOB_DONE
    assert job.hits == 3
    assert job.query is not None
    assert "8.8.8.8" in job.query


async def test_worker_drains_to_empty_queue(
    respx_router: respx.Router,
    migrated_db: core_db.Database,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-1:udmSearch").mock(
        return_value=httpx.Response(200, json={"events": [], "total_events": 0})
    )
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="ipv4", value="1.1.1.1")
    for _ in range(3):
        store.enqueue_retro_hunt(ioc_id, retro_hunt.CHRONICLE_PLATFORM)
    worker = retro_hunt.RetroHuntWorker(_client(), store)
    result = await worker.run_once()
    assert result.drained == 3
    assert result.succeeded == 3
    # No more queued jobs.
    assert store.next_pending_job(retro_hunt.CHRONICLE_PLATFORM) is None


async def test_worker_respects_max_jobs(
    respx_router: respx.Router,
    migrated_db: core_db.Database,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-1:udmSearch").mock(
        return_value=httpx.Response(200, json={"events": [], "total_events": 0})
    )
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="ipv4", value="1.1.1.1")
    for _ in range(5):
        store.enqueue_retro_hunt(ioc_id, retro_hunt.CHRONICLE_PLATFORM)
    worker = retro_hunt.RetroHuntWorker(_client(), store)
    result = await worker.run_once(max_jobs=2)
    assert result.drained == 2
    # 3 jobs still queued.
    queued = store.recent_jobs(platform=retro_hunt.CHRONICLE_PLATFORM, status=store_mod.JOB_QUEUED)
    assert len(queued) == 3


async def test_worker_records_api_failure(
    respx_router: respx.Router,
    migrated_db: core_db.Database,
) -> None:
    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-1:udmSearch").mock(
        return_value=httpx.Response(401, text="bad creds")
    )
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="ipv4", value="1.1.1.1")
    job_id = store.enqueue_retro_hunt(ioc_id, retro_hunt.CHRONICLE_PLATFORM)
    worker = retro_hunt.RetroHuntWorker(_client(), store)
    result = await worker.run_once()
    assert result.drained == 1
    assert result.failed == 1
    assert result.succeeded == 0
    job = store.get_job(job_id)
    assert job is not None
    assert job.status == store_mod.JOB_ERROR
    assert job.error is not None
    assert "401" in job.error


async def test_worker_skips_unsupported_ioc_type(
    respx_router: respx.Router,
    migrated_db: core_db.Database,
) -> None:
    """Job whose IOC type isn't UDM-mappable goes to error/skipped."""
    store = store_mod.IOCStore(migrated_db)
    # Hand-insert an IOC with a type the schema accepts but the query
    # builder doesn't (synthetic — bypass normalize_value).
    conn = migrated_db.open()
    conn.execute(
        "INSERT INTO iocs (type, value, first_seen, last_seen) VALUES (?, ?, ?, ?)",
        (
            "synthetic-not-supported",
            "x",
            "2026-01-01T00:00:00.000000Z",
            "2026-01-01T00:00:00.000000Z",
        ),
    )
    ioc_id = int(
        conn.execute(
            "SELECT id FROM iocs WHERE type = ? LIMIT 1",
            ("synthetic-not-supported",),
        ).fetchone()["id"]
    )
    job_id = store.enqueue_retro_hunt(ioc_id, retro_hunt.CHRONICLE_PLATFORM)
    worker = retro_hunt.RetroHuntWorker(_client(), store)
    result = await worker.run_once()
    assert result.skipped == 1
    job = store.get_job(job_id)
    assert job is not None
    assert job.status == store_mod.JOB_ERROR
    assert "synthetic-not-supported" in (job.error or "")


async def test_worker_handles_deleted_ioc(
    respx_router: respx.Router,
    migrated_db: core_db.Database,
) -> None:
    """If an IOC is deleted between enqueue and worker, the job FK cascade
    drops the job too — there's nothing for the worker to process."""
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="ipv4", value="1.1.1.1")
    store.enqueue_retro_hunt(ioc_id, retro_hunt.CHRONICLE_PLATFORM)
    conn = migrated_db.open()
    conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
    worker = retro_hunt.RetroHuntWorker(_client(), store)
    result = await worker.run_once()
    assert result.drained == 0


async def test_worker_one_failure_does_not_stop_others(
    respx_router: respx.Router,
    migrated_db: core_db.Database,
) -> None:
    """Mix of success + non-retryable 4xx across multiple IOCs.

    HardenedClient auto-retries 5xx, so we use 401 (not retryable) for
    the first call to model an immediate per-IOC failure.
    """
    call_count = {"n": 0}

    def _resp(_request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return httpx.Response(401, text="bad token")
        return httpx.Response(200, json={"events": [{"x": 1}], "total_events": 1})

    respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-1:udmSearch").mock(
        side_effect=_resp
    )
    store = store_mod.IOCStore(migrated_db)
    ioc_a = _seed_ioc(store, type_="ipv4", value="8.8.8.8")
    ioc_b = _seed_ioc(store, type_="ipv4", value="1.1.1.1")
    store.enqueue_retro_hunt(ioc_a, retro_hunt.CHRONICLE_PLATFORM)
    store.enqueue_retro_hunt(ioc_b, retro_hunt.CHRONICLE_PLATFORM)
    worker = retro_hunt.RetroHuntWorker(_client(), store)
    result = await worker.run_once()
    assert result.drained == 2
    assert result.failed == 1
    assert result.succeeded == 1


async def test_worker_max_jobs_validation() -> None:
    store = store_mod.IOCStore.__new__(store_mod.IOCStore)
    worker = retro_hunt.RetroHuntWorker(_client(), store)
    with pytest.raises(ValueError):
        await worker.run_once(max_jobs=0)


async def test_worker_lookback_and_limit_passed_through(
    respx_router: respx.Router,
    migrated_db: core_db.Database,
) -> None:
    """Worker forwards lookback_hours + limit_per_query to the UDM call."""
    import json as _json

    route = respx_router.post("https://us-chronicle.googleapis.com/v1alpha/cust-1:udmSearch").mock(
        return_value=httpx.Response(200, json={"events": [], "total_events": 0})
    )
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed_ioc(store, type_="sha256", value="a" * 64)
    store.enqueue_retro_hunt(ioc_id, retro_hunt.CHRONICLE_PLATFORM)
    worker = retro_hunt.RetroHuntWorker(_client(), store, lookback_hours=72, limit_per_query=200)
    await worker.run_once()
    body = _json.loads(route.calls[0].request.content)
    assert body["limit"] == 200
    # 72h lookback ≈ start_time exactly 72h before end_time. We just check
    # that the field is present and non-empty.
    assert body["time_range"]["start_time"]
