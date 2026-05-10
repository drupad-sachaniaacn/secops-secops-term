"""NVD (NIST CVE) provider — CVE pull + reachability health probe."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from types import ModuleType

import httpx
import pytest
import respx

from secops_term.core import secrets as secrets_mod
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers import nvd as nvd_mod

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def _make_fake_keyring(token: str | None = "test-nvd-key") -> ModuleType:
    class _FakeBackend:
        pass

    backend = _FakeBackend()
    store: dict[tuple[str, str], str] = {}
    if token is not None:
        store[("secops-term:intel.nvd:default", "api_key")] = token

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
def fake_secrets_with_key() -> Iterator[None]:
    secrets_mod.reset_manager_for_tests()
    cfg = secrets_mod.SecretsConfig(keyring_module=_make_fake_keyring())
    secrets_mod.get_manager(cfg)
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


@pytest.fixture
def fake_secrets_no_key() -> Iterator[None]:
    secrets_mod.reset_manager_for_tests()
    cfg = secrets_mod.SecretsConfig(keyring_module=_make_fake_keyring(token=None))
    secrets_mod.get_manager(cfg)
    try:
        yield
    finally:
        secrets_mod.reset_manager_for_tests()


_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cve_vuln(
    cve_id: str = "CVE-2024-12345",
    base_score: float = 9.8,
    severity: str = "CRITICAL",
    description: str = "A critical buffer overflow in Example Software.",
) -> dict:
    return {
        "cve": {
            "id": cve_id,
            "published": "2024-06-01T10:00:00.000",
            "lastModified": "2024-06-02T08:00:00.000",
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": base_score,
                            "baseSeverity": severity,
                        },
                    }
                ]
            },
        }
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registered() -> None:
    assert "nvd" in PROVIDERS
    assert PROVIDERS.get("nvd") is nvd_mod.NVDProvider


# ---------------------------------------------------------------------------
# from_config
# ---------------------------------------------------------------------------


def test_from_config_defaults() -> None:
    p = nvd_mod.NVDProvider.from_config("default", {})
    assert p.instance == "default"
    assert p._days_back == nvd_mod._DEFAULT_DAYS_BACK
    assert p._min_cvss_v3 == nvd_mod._DEFAULT_MIN_CVSS
    assert p._limit == nvd_mod._DEFAULT_LIMIT


def test_from_config_custom() -> None:
    p = nvd_mod.NVDProvider.from_config("prod", {"days_back": 14, "min_cvss_v3": 9.0, "limit": 50})
    assert p._days_back == 14
    assert p._min_cvss_v3 == 9.0
    assert p._limit == 50


def test_from_config_clamps_limit() -> None:
    p = nvd_mod.NVDProvider.from_config("default", {"limit": 9999})
    assert p._limit == nvd_mod._MAX_LIMIT  # capped at 2000


# ---------------------------------------------------------------------------
# pull()
# ---------------------------------------------------------------------------


async def test_pull_works_without_api_key(
    respx_router: respx.Router, fake_secrets_no_key: None
) -> None:
    """NVD is public — pull succeeds even with no API key configured."""
    respx_router.get(_NVD_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "totalResults": 1,
                "vulnerabilities": [_cve_vuln()],
            },
        )
    )
    p = nvd_mod.NVDProvider("default", min_cvss_v3=0.0)
    records = await p.pull()
    assert len(records) == 1
    assert records[0].value == "CVE-2024-12345"


async def test_pull_maps_cves(respx_router: respx.Router, fake_secrets_with_key: None) -> None:
    respx_router.get(_NVD_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "totalResults": 2,
                "vulnerabilities": [
                    _cve_vuln("CVE-2024-00001", 9.8, "CRITICAL"),
                    _cve_vuln("CVE-2024-00002", 7.5, "HIGH"),
                ],
            },
        )
    )
    p = nvd_mod.NVDProvider("default", min_cvss_v3=0.0)
    records = await p.pull()
    assert len(records) == 2
    assert all(r.type == "cve" for r in records)
    assert {r.value for r in records} == {"CVE-2024-00001", "CVE-2024-00002"}
    assert all(r.source == "nvd:default" for r in records)
    # source_ref points to the NVD detail page.
    assert all("nvd.nist.gov/vuln/detail" in (r.source_ref or "") for r in records)
    # Severity becomes a tag.
    assert any(r.tags == ("critical",) for r in records)
    assert any(r.tags == ("high",) for r in records)


async def test_pull_sends_api_key_header(
    respx_router: respx.Router, fake_secrets_with_key: None
) -> None:
    route = respx_router.get(_NVD_URL).mock(
        return_value=httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})
    )
    p = nvd_mod.NVDProvider("default")
    await p.pull()
    assert route.calls[0].request.headers.get("apiKey") == "test-nvd-key"


async def test_pull_no_api_key_header_when_unconfigured(
    respx_router: respx.Router, fake_secrets_no_key: None
) -> None:
    route = respx_router.get(_NVD_URL).mock(
        return_value=httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})
    )
    p = nvd_mod.NVDProvider("default")
    await p.pull()
    assert "apiKey" not in route.calls[0].request.headers


async def test_pull_filters_by_min_cvss(
    respx_router: respx.Router, fake_secrets_no_key: None
) -> None:
    respx_router.get(_NVD_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "totalResults": 2,
                "vulnerabilities": [
                    _cve_vuln("CVE-2024-HIGH", 7.5, "HIGH"),
                    _cve_vuln("CVE-2024-LOW", 3.1, "LOW"),
                ],
            },
        )
    )
    p = nvd_mod.NVDProvider("default", min_cvss_v3=7.0)
    records = await p.pull()
    assert len(records) == 1
    assert records[0].value == "CVE-2024-HIGH"


async def test_pull_uses_since_as_start_date(
    respx_router: respx.Router, fake_secrets_no_key: None
) -> None:
    route = respx_router.get(_NVD_URL).mock(
        return_value=httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})
    )
    since = datetime(2026, 1, 15, 0, 0, 0, tzinfo=UTC)
    p = nvd_mod.NVDProvider("default")
    await p.pull(since=since)
    url_str = str(route.calls[0].request.url)
    assert "2026-01-15" in url_str


async def test_pull_non_200_returns_empty(
    respx_router: respx.Router, fake_secrets_no_key: None
) -> None:
    respx_router.get(_NVD_URL).mock(return_value=httpx.Response(503))
    p = nvd_mod.NVDProvider("default")
    assert await p.pull() == []


async def test_pull_description_in_context(
    respx_router: respx.Router, fake_secrets_no_key: None
) -> None:
    desc = "Remote code execution via heap overflow in the foo component."
    respx_router.get(_NVD_URL).mock(
        return_value=httpx.Response(
            200,
            json={"totalResults": 1, "vulnerabilities": [_cve_vuln(description=desc)]},
        )
    )
    p = nvd_mod.NVDProvider("default", min_cvss_v3=0.0)
    records = await p.pull()
    assert records[0].context == desc


# ---------------------------------------------------------------------------
# health_check()
# ---------------------------------------------------------------------------


async def test_health_check_ok(respx_router: respx.Router, fake_secrets_no_key: None) -> None:
    respx_router.get(_NVD_URL).mock(
        return_value=httpx.Response(200, json={"totalResults": 250_000, "vulnerabilities": []})
    )
    p = nvd_mod.NVDProvider("default")
    status = await p.health_check()
    assert status.ok is True
    assert "reachable" in status.detail
    assert "unauthenticated" in status.detail


async def test_health_check_authenticated(
    respx_router: respx.Router, fake_secrets_with_key: None
) -> None:
    respx_router.get(_NVD_URL).mock(
        return_value=httpx.Response(200, json={"totalResults": 250_000, "vulnerabilities": []})
    )
    p = nvd_mod.NVDProvider("default")
    status = await p.health_check()
    assert status.ok is True
    assert "authenticated" in status.detail


async def test_health_check_non_200(respx_router: respx.Router, fake_secrets_no_key: None) -> None:
    respx_router.get(_NVD_URL).mock(return_value=httpx.Response(503))
    p = nvd_mod.NVDProvider("default")
    status = await p.health_check()
    assert status.ok is False
    assert "503" in status.detail
