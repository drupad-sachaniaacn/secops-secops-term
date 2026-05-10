"""IOC store: retro_hunt_jobs CRUD + claim semantics."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secops_term.core import db as core_db
from secops_term.intel import store as store_mod
from secops_term.intel.providers.base import IntelRecord


def _seed(store: store_mod.IOCStore, *, type_: str = "ipv4", value: str = "8.8.8.8") -> int:
    ioc_id, _ = store.upsert(
        IntelRecord(
            source="test:default",
            type=type_,
            value=value,
            fetched_at=datetime.now(UTC),
        )
    )
    return ioc_id


# Enqueue


def test_enqueue_returns_id_and_inserts_queued_row(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    job_id = store.enqueue_retro_hunt(ioc_id, "chronicle")
    assert job_id > 0
    job = store.get_job(job_id)
    assert job is not None
    assert job.status == store_mod.JOB_QUEUED
    assert job.ioc_id == ioc_id
    assert job.platform == "chronicle"
    assert job.hits is None
    assert job.error is None
    assert job.completed_at is None


def test_enqueue_rejects_empty_platform(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    with pytest.raises(store_mod.IOCStoreError):
        store.enqueue_retro_hunt(ioc_id, "")


def test_multiple_enqueues_for_same_ioc_are_independent(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    j1 = store.enqueue_retro_hunt(ioc_id, "chronicle")
    j2 = store.enqueue_retro_hunt(ioc_id, "chronicle")
    j3 = store.enqueue_retro_hunt(ioc_id, "vision_one")
    assert {j1, j2, j3} == {j1, j2, j3}  # all distinct
    jobs = store.jobs_for_ioc(ioc_id)
    assert len(jobs) == 3


# Atomic claim (next_pending_job)


def test_next_pending_job_returns_oldest_first(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    j1 = store.enqueue_retro_hunt(ioc_id, "chronicle")
    j2 = store.enqueue_retro_hunt(ioc_id, "chronicle")
    j3 = store.enqueue_retro_hunt(ioc_id, "chronicle")

    first = store.next_pending_job("chronicle")
    second = store.next_pending_job("chronicle")
    third = store.next_pending_job("chronicle")
    fourth = store.next_pending_job("chronicle")

    assert first is not None and first.id == j1
    assert second is not None and second.id == j2
    assert third is not None and third.id == j3
    assert fourth is None  # queue drained


def test_next_pending_job_transitions_status_to_running(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    job_id = store.enqueue_retro_hunt(ioc_id, "chronicle")

    claimed = store.next_pending_job("chronicle")
    assert claimed is not None
    assert claimed.status == store_mod.JOB_RUNNING
    # Persisted: a re-read sees the new status.
    re_read = store.get_job(job_id)
    assert re_read is not None
    assert re_read.status == store_mod.JOB_RUNNING


def test_next_pending_job_per_platform(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    chronicle_id = store.enqueue_retro_hunt(ioc_id, "chronicle")
    v1_id = store.enqueue_retro_hunt(ioc_id, "vision_one")

    chronicle_job = store.next_pending_job("chronicle")
    v1_job = store.next_pending_job("vision_one")
    assert chronicle_job is not None and chronicle_job.id == chronicle_id
    assert v1_job is not None and v1_job.id == v1_id


def test_next_pending_job_skips_running_and_done_and_error(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    j_done = store.enqueue_retro_hunt(ioc_id, "chronicle")
    store.next_pending_job("chronicle")
    store.complete_job(j_done, hits=5, query='principal.ip = "x"')

    j_error = store.enqueue_retro_hunt(ioc_id, "chronicle")
    store.next_pending_job("chronicle")
    store.fail_job(j_error, "broken")

    j_queued = store.enqueue_retro_hunt(ioc_id, "chronicle")
    claimed = store.next_pending_job("chronicle")
    assert claimed is not None
    assert claimed.id == j_queued


def test_next_pending_job_returns_none_when_empty(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    assert store.next_pending_job("chronicle") is None


def test_next_pending_job_rejects_empty_platform(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    with pytest.raises(store_mod.IOCStoreError):
        store.next_pending_job("")


# Complete + fail


def test_complete_job_sets_done_with_hits_query(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    job_id = store.enqueue_retro_hunt(ioc_id, "chronicle")
    store.next_pending_job("chronicle")  # → running
    store.complete_job(job_id, hits=12, query='principal.ip = "8.8.8.8"')
    job = store.get_job(job_id)
    assert job is not None
    assert job.status == store_mod.JOB_DONE
    assert job.hits == 12
    assert job.query == 'principal.ip = "8.8.8.8"'
    assert job.completed_at is not None
    assert job.error is None


def test_complete_job_rejects_negative_hits(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    job_id = store.enqueue_retro_hunt(ioc_id, "chronicle")
    with pytest.raises(store_mod.IOCStoreError):
        store.complete_job(job_id, hits=-1, query="x")


def test_fail_job_sets_error_and_completed_at(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    job_id = store.enqueue_retro_hunt(ioc_id, "chronicle")
    store.next_pending_job("chronicle")
    store.fail_job(job_id, "Chronicle 503")
    job = store.get_job(job_id)
    assert job is not None
    assert job.status == store_mod.JOB_ERROR
    assert job.error == "Chronicle 503"
    assert job.completed_at is not None


def test_fail_job_truncates_long_error(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    job_id = store.enqueue_retro_hunt(ioc_id, "chronicle")
    store.fail_job(job_id, "X" * 5000)
    job = store.get_job(job_id)
    assert job is not None
    assert job.error is not None
    assert len(job.error) <= 2000


# get_job / recent_jobs / jobs_for_ioc


def test_get_job_missing_returns_none(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    assert store.get_job(999) is None


def test_recent_jobs_filters_by_platform_and_status(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    chronicle_done_id = store.enqueue_retro_hunt(ioc_id, "chronicle")
    store.complete_job(chronicle_done_id, hits=1, query="x")
    chronicle_q = store.enqueue_retro_hunt(ioc_id, "chronicle")
    v1_q = store.enqueue_retro_hunt(ioc_id, "vision_one")

    chronicle_jobs = store.recent_jobs(platform="chronicle")
    v1_jobs = store.recent_jobs(platform="vision_one")
    queued_only = store.recent_jobs(status=store_mod.JOB_QUEUED)
    chronicle_done = store.recent_jobs(platform="chronicle", status=store_mod.JOB_DONE)

    assert {j.id for j in chronicle_jobs} == {chronicle_done_id, chronicle_q}
    assert {j.id for j in v1_jobs} == {v1_q}
    assert {j.id for j in queued_only} == {chronicle_q, v1_q}
    assert {j.id for j in chronicle_done} == {chronicle_done_id}


def test_recent_jobs_unknown_status_raises(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    with pytest.raises(store_mod.IOCStoreError):
        store.recent_jobs(status="not-a-status")


def test_recent_jobs_limit_bounded(
    migrated_db: core_db.Database,
) -> None:
    store = store_mod.IOCStore(migrated_db)
    with pytest.raises(store_mod.IOCStoreError):
        store.recent_jobs(limit=20_000)
    with pytest.raises(store_mod.IOCStoreError):
        store.recent_jobs(limit=0)


def test_jobs_for_ioc_returns_newest_first(
    migrated_db: core_db.Database,
) -> None:
    import time as _time

    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    j1 = store.enqueue_retro_hunt(ioc_id, "chronicle")
    _time.sleep(0.001)  # different created_at
    j2 = store.enqueue_retro_hunt(ioc_id, "chronicle")
    _time.sleep(0.001)
    j3 = store.enqueue_retro_hunt(ioc_id, "vision_one")
    jobs = store.jobs_for_ioc(ioc_id)
    assert [j.id for j in jobs] == [j3, j2, j1]


# IOC delete cascades


def test_delete_ioc_cascades_to_retro_hunt_jobs(
    migrated_db: core_db.Database,
) -> None:
    """``ON DELETE CASCADE`` on ``retro_hunt_jobs.ioc_id`` removes child jobs."""
    store = store_mod.IOCStore(migrated_db)
    ioc_id = _seed(store)
    job_id = store.enqueue_retro_hunt(ioc_id, "chronicle")
    conn = migrated_db.open()
    conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
    assert store.get_job(job_id) is None
