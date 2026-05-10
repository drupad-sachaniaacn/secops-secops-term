"""RSS provider — feed parsing + summary IOC extraction + health probe."""

from __future__ import annotations

import socket
from collections.abc import Iterator

import httpx
import pytest
import respx

from secops_term.core import url_guard
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers import rss as rss_mod
from secops_term.intel.providers.base import IntelProviderError

_MANDIANT_FEED_URL = "https://research.example.com/feed.rss"


_SAMPLE_RSS = """\
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
  <title>Threat Research</title>
  <link>https://research.example.com/</link>
  <description>Latest threat reports</description>
  <item>
    <title>New Emotet C2 cluster</title>
    <link>https://research.example.com/posts/emotet-1</link>
    <pubDate>Wed, 01 Jan 2026 12:00:00 GMT</pubDate>
    <description>Observed C2 at 8.8.8.8 contacting hxxps://evil[.]example[.]com/c2 — see CVE-2024-1234.</description>
  </item>
  <item>
    <title>QakBot resurgence</title>
    <link>https://research.example.com/posts/qakbot-1</link>
    <pubDate>Fri, 03 Jan 2026 09:00:00 GMT</pubDate>
    <description>Sample sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa drops payload.</description>
  </item>
</channel>
</rss>
"""


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve any host to a fake public IP so ``url_guard`` accepts it."""
    monkeypatch.setattr(
        url_guard,
        "_resolve_all",
        lambda host, port: [("93.184.216.34", socket.AF_INET)],
    )


# Registry / construction


def test_registered() -> None:
    assert "rss" in PROVIDERS
    assert PROVIDERS.get("rss") is rss_mod.RSSProvider


def test_from_config_requires_feed_url() -> None:
    with pytest.raises(IntelProviderError):
        rss_mod.RSSProvider.from_config("default", {})


def test_from_config_rejects_non_string_feed_url() -> None:
    with pytest.raises(IntelProviderError):
        rss_mod.RSSProvider.from_config("default", {"feed_url": 42})


def test_from_config_defaults_scrape_articles_false() -> None:
    p = rss_mod.RSSProvider.from_config("mandiant", {"feed_url": _MANDIANT_FEED_URL})
    assert p.feed_url == _MANDIANT_FEED_URL
    assert p.scrape_articles is False
    assert p.respect_robots is True


def test_from_config_accepts_overrides() -> None:
    p = rss_mod.RSSProvider.from_config(
        "talos",
        {
            "feed_url": _MANDIANT_FEED_URL,
            "scrape_articles": True,
            "respect_robots": False,
        },
    )
    assert p.scrape_articles is True
    assert p.respect_robots is False


# Pull


async def test_pull_extracts_iocs_from_summaries(
    respx_router: respx.Router, fake_dns: None
) -> None:
    respx_router.get(_MANDIANT_FEED_URL).mock(
        return_value=httpx.Response(
            200,
            text=_SAMPLE_RSS,
            headers={"Content-Type": "application/rss+xml"},
        )
    )
    p = rss_mod.RSSProvider("mandiant", _MANDIANT_FEED_URL)
    records = await p.pull()
    by_type = {(r.type, r.value) for r in records}
    assert ("ipv4", "8.8.8.8") in by_type
    assert ("url", "https://evil.example.com/c2") in by_type
    assert ("cve", "CVE-2024-1234") in by_type
    assert ("sha256", "a" * 64) in by_type
    assert all(r.source == "rss:mandiant" for r in records)


async def test_pull_filters_by_since(respx_router: respx.Router, fake_dns: None) -> None:
    from datetime import UTC, datetime

    respx_router.get(_MANDIANT_FEED_URL).mock(
        return_value=httpx.Response(
            200,
            text=_SAMPLE_RSS,
            headers={"Content-Type": "application/rss+xml"},
        )
    )
    p = rss_mod.RSSProvider("mandiant", _MANDIANT_FEED_URL)
    # Cut at Jan 2 — only the Jan 3 entry (with the sha256) survives.
    records = await p.pull(since=datetime(2026, 1, 2, tzinfo=UTC))
    types = {r.type for r in records}
    assert "sha256" in types
    # The Jan 1 entry is filtered out, so its 8.8.8.8 should NOT appear.
    assert not any(r.value == "8.8.8.8" for r in records)


async def test_pull_rejects_private_feed_url() -> None:
    p = rss_mod.RSSProvider("evil", "https://127.0.0.1/feed")
    with pytest.raises(url_guard.URLGuardError):
        await p.pull()


async def test_pull_propagates_non_200(respx_router: respx.Router, fake_dns: None) -> None:
    respx_router.get(_MANDIANT_FEED_URL).mock(return_value=httpx.Response(404))
    p = rss_mod.RSSProvider("mandiant", _MANDIANT_FEED_URL)
    with pytest.raises(IntelProviderError):
        await p.pull()


# scrape_articles=True


async def test_pull_scrapes_articles_when_opted_in(
    respx_router: respx.Router, fake_dns: None
) -> None:
    respx_router.get(_MANDIANT_FEED_URL).mock(
        return_value=httpx.Response(
            200, text=_SAMPLE_RSS, headers={"Content-Type": "application/rss+xml"}
        )
    )
    # Mock both article URLs.
    respx_router.get("https://research.example.com/robots.txt").mock(
        return_value=httpx.Response(404)
    )
    respx_router.get("https://research.example.com/posts/emotet-1").mock(
        return_value=httpx.Response(
            200,
            text="<html><body><p>Article body: 5.5.5.5 traffic</p></body></html>",
            headers={"Content-Type": "text/html"},
        )
    )
    respx_router.get("https://research.example.com/posts/qakbot-1").mock(
        return_value=httpx.Response(
            200,
            text="<html><body><p>Article body: 6.6.6.6 traffic</p></body></html>",
            headers={"Content-Type": "text/html"},
        )
    )
    p = rss_mod.RSSProvider("mandiant", _MANDIANT_FEED_URL, scrape_articles=True)
    records = await p.pull()
    values = {r.value for r in records}
    # Article-body IOCs surface alongside summary IOCs.
    assert "5.5.5.5" in values
    assert "6.6.6.6" in values


# Health check


async def test_health_check_succeeds_on_valid_feed(
    respx_router: respx.Router, fake_dns: None
) -> None:
    respx_router.get(_MANDIANT_FEED_URL).mock(
        return_value=httpx.Response(
            200, text=_SAMPLE_RSS, headers={"Content-Type": "application/rss+xml"}
        )
    )
    p = rss_mod.RSSProvider("mandiant", _MANDIANT_FEED_URL)
    status = await p.health_check()
    assert status.ok is True
    assert "2 entries" in status.detail


async def test_health_check_fails_on_404(respx_router: respx.Router, fake_dns: None) -> None:
    respx_router.get(_MANDIANT_FEED_URL).mock(return_value=httpx.Response(404))
    p = rss_mod.RSSProvider("mandiant", _MANDIANT_FEED_URL)
    status = await p.health_check()
    assert status.ok is False


async def test_health_check_fails_on_private_url() -> None:
    p = rss_mod.RSSProvider("evil", "https://127.0.0.1/feed")
    status = await p.health_check()
    assert status.ok is False
    assert "rejected" in status.detail
