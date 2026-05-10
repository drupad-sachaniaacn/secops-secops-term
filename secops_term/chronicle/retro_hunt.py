"""Chronicle retro-hunt query builder + worker.

Per brief v3 §6.2: ad-hoc retro hunt via UDM Search API. Not Rules Engine,
not YARA-L deployment.

Query mappings (honouring the user's documented preference for bare UDM
filter expressions — no ``rule {}`` wrapper):

==========  ===============================================================
IOC type    UDM expression
==========  ===============================================================
ipv4 / ipv6 ``principal.ip = "X" OR target.ip = "X" OR src.ip = "X"
            OR dst.ip = "X"``
domain      ``network.dns.questions.name = "X" OR principal.domain.name =
            "X" OR target.domain.name = "X"``
url         ``network.http.referral_url = "X" OR target.url = "X"``
sha256      ``target.file.sha256 = "X"``
sha1        ``target.file.sha1 = "X"``
md5         ``target.file.md5 = "X"``
email       ``network.email.from = "X" OR network.email.to = "X"``
cve         ``vulnerability.about.vulnerability.cve_id = "X"``
==========  ===============================================================

The :class:`RetroHuntWorker` drains :class:`RetroHuntJob` rows from the
store (status ``queued`` → ``running`` → ``done`` / ``error``), runs the
generated UDM search via :class:`ChronicleClient`, and records hit counts.
"""

from __future__ import annotations

from dataclasses import dataclass

from secops_term.chronicle.client import (
    ChronicleAPIError,
    ChronicleClient,
    ChronicleError,
)
from secops_term.intel import store as store_mod

# The platform string used in ``retro_hunt_jobs.platform`` for Chronicle.
CHRONICLE_PLATFORM = "chronicle"


class UnsupportedIOCType(Exception):
    """The IOC type is not supported by the Chronicle UDM query builder."""


def build_udm_query(ioc_type: str, ioc_value: str) -> str:
    """Return a UDM filter expression for the given IOC.

    Raises :class:`UnsupportedIOCType` if the IOC type isn't mapped.
    """
    val = _escape(ioc_value)
    if ioc_type in ("ipv4", "ipv6"):
        return (
            f'principal.ip = "{val}" OR target.ip = "{val}" OR src.ip = "{val}" OR dst.ip = "{val}"'
        )
    if ioc_type == "domain":
        return (
            f'network.dns.questions.name = "{val}" '
            f'OR principal.domain.name = "{val}" '
            f'OR target.domain.name = "{val}"'
        )
    if ioc_type == "url":
        return f'network.http.referral_url = "{val}" OR target.url = "{val}"'
    if ioc_type == "sha256":
        return f'target.file.sha256 = "{val}"'
    if ioc_type == "sha1":
        return f'target.file.sha1 = "{val}"'
    if ioc_type == "md5":
        return f'target.file.md5 = "{val}"'
    if ioc_type == "email":
        return f'network.email.from = "{val}" OR network.email.to = "{val}"'
    if ioc_type == "cve":
        return f'vulnerability.about.vulnerability.cve_id = "{val}"'
    raise UnsupportedIOCType(f"no Chronicle UDM query for IOC type {ioc_type!r}")


def _escape(value: str) -> str:
    """Escape backslash and double-quote for UDM string literals.

    Defence in depth — :func:`secops_term.intel.ioc.normalize_value`
    already rejects values containing quotes for every supported type, so
    this is a belt-and-suspenders pass that keeps malformed input from
    forming a syntactically broken (or worse, injection-attempted) query.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


@dataclass(frozen=True)
class RunResult:
    """Outcome of one :meth:`RetroHuntWorker.run_once` invocation."""

    drained: int  # jobs claimed from the queue
    succeeded: int  # job → done
    failed: int  # job → error from API/transport failure
    skipped: int  # job → error because IOC vanished or type unsupported

    @property
    def total(self) -> int:
        return self.drained


class RetroHuntWorker:
    """Drains queued Chronicle retro-hunt jobs from the store."""

    def __init__(
        self,
        client: ChronicleClient,
        store: store_mod.IOCStore,
        *,
        lookback_hours: int = 24 * 30,
        limit_per_query: int = 1000,
    ) -> None:
        self._client = client
        self._store = store
        self._lookback_hours = lookback_hours
        self._limit_per_query = limit_per_query

    async def run_once(self, *, max_jobs: int = 50) -> RunResult:
        """Drain up to ``max_jobs`` queued jobs and return per-class counts.

        Per-job exceptions are caught and recorded as ``error`` rows; the
        loop continues so one bad IOC doesn't stop the rest of the batch.
        """
        if max_jobs < 1:
            raise ValueError(f"max_jobs must be >= 1, got {max_jobs}")
        drained = succeeded = failed = skipped = 0
        for _ in range(max_jobs):
            job = self._store.next_pending_job(CHRONICLE_PLATFORM)
            if job is None:
                break
            drained += 1
            ioc = self._store.get_by_id(job.ioc_id)
            if ioc is None:
                self._store.fail_job(job.id, f"IOC id={job.ioc_id} no longer present")
                skipped += 1
                continue
            try:
                query = build_udm_query(ioc.type, ioc.value)
            except UnsupportedIOCType as exc:
                self._store.fail_job(job.id, str(exc))
                skipped += 1
                continue
            try:
                result = await self._client.udm_search(
                    query,
                    lookback_hours=self._lookback_hours,
                    limit=self._limit_per_query,
                )
            except ChronicleAPIError as exc:
                self._store.fail_job(job.id, f"Chronicle API: HTTP {exc.status_code}")
                failed += 1
                continue
            except ChronicleError as exc:
                self._store.fail_job(job.id, f"Chronicle: {exc}")
                failed += 1
                continue
            except Exception as exc:
                self._store.fail_job(job.id, f"{type(exc).__name__}: {exc}")
                failed += 1
                continue
            hits = result.total_events if result.total_events is not None else len(result.events)
            self._store.complete_job(job.id, hits=hits, query=query)
            succeeded += 1
        return RunResult(
            drained=drained,
            succeeded=succeeded,
            failed=failed,
            skipped=skipped,
        )


__all__ = [
    "CHRONICLE_PLATFORM",
    "RetroHuntWorker",
    "RunResult",
    "UnsupportedIOCType",
    "build_udm_query",
]
