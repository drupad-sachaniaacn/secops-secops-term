"""Generic RSS / Atom feed provider — multi-instance.

Per brief v3 §6.1: ship example config for Mandiant, Talos, MSRC, Trend
Micro Research, CISA, Unit 42 (these are operator-curated feed URLs that
the user wires up via ``secops-term config intel rss --instance <name>``).

Each instance has its own config block:

.. code-block:: toml

    [intel_providers.rss.mandiant]
    enabled = true
    feed_url = "https://www.mandiant.com/resources/blog/rss.xml"
    scrape_articles = false   # if true, fetch each entry's link and run the
                              # scraper over the full article body
    respect_robots = true     # only relevant when scrape_articles=true

In Phase 1 the feed itself doesn't require auth; if a future feed needs
``api_token`` we'll honour the same keyring conventions as the other
providers.

Health check: ``GET feed_url`` and confirm ``feedparser`` parses at least
one entry.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, ClassVar

import feedparser

from secops_term.core import url_guard
from secops_term.core.health import HealthStatus
from secops_term.core.http import FEED_RESPONSE_CAP_BYTES, HardenedClient, HTTPConfig
from secops_term.intel import scraper as scraper_mod
from secops_term.intel.providers import PROVIDERS
from secops_term.intel.providers.base import IntelProviderError, IntelRecord


@PROVIDERS.register("rss")
class RSSProvider:
    """Generic RSS/Atom feed provider.

    Multi-instance: each named instance is one feed URL. Phase 1 ships
    summary-based extraction (run :func:`extract_iocs_from_text` over each
    entry's title + summary). With ``scrape_articles=true`` in config, also
    fetches the article URL and runs the full scraper over the body — at
    that point ``robots.txt`` is honoured per the scraper's defaults.
    """

    name: ClassVar[str] = "rss"

    def __init__(
        self,
        instance: str,
        feed_url: str,
        *,
        scrape_articles: bool = False,
        respect_robots: bool = True,
    ) -> None:
        self.instance = instance
        self._feed_url = feed_url
        self._scrape_articles = scrape_articles
        self._respect_robots = respect_robots

    @classmethod
    def from_config(cls, instance: str, cfg: Mapping[str, Any]) -> RSSProvider:
        feed_url = cfg.get("feed_url")
        if not isinstance(feed_url, str) or not feed_url.strip():
            raise IntelProviderError(f"{cls.name}:{instance}: feed_url is required (string)")
        scrape = bool(cfg.get("scrape_articles", False))
        respect = bool(cfg.get("respect_robots", True))
        return cls(
            instance,
            feed_url.strip(),
            scrape_articles=scrape,
            respect_robots=respect,
        )

    @property
    def feed_url(self) -> str:
        return self._feed_url

    @property
    def scrape_articles(self) -> bool:
        return self._scrape_articles

    @property
    def respect_robots(self) -> bool:
        return self._respect_robots

    async def pull(self, *, since: datetime | None = None) -> list[IntelRecord]:
        url_guard.validate_url(self._feed_url)
        feed_text = await _fetch_feed(self._feed_url)
        parsed = feedparser.parse(feed_text)
        records: list[IntelRecord] = []
        fetched_at = datetime.now(UTC)
        for entry in parsed.entries:
            published = _entry_datetime(entry)
            if since is not None and published is not None and published < since:
                continue
            text = _entry_text(entry)
            for ioc in scraper_mod.extract_iocs_from_text(text):
                records.append(
                    IntelRecord(
                        source=f"rss:{self.instance}",
                        type=ioc.type,
                        value=ioc.value,
                        fetched_at=fetched_at,
                        context=ioc.context,
                        source_ref=str(entry.get("link") or entry.get("id") or "") or None,
                    )
                )
            if self._scrape_articles:
                link = entry.get("link")
                if isinstance(link, str) and link:
                    records.extend(await self._scrape_article(link))
        return records

    async def health_check(self) -> HealthStatus:
        """Fetch the feed and confirm ``feedparser`` parses at least one entry."""
        started = time.monotonic()
        try:
            url_guard.validate_url(self._feed_url)
        except url_guard.URLGuardError as exc:
            return _failed(f"feed_url rejected: {exc}", started)
        try:
            text = await _fetch_feed(self._feed_url)
        except Exception as exc:
            return _failed(f"{type(exc).__name__}: {exc}", started)
        parsed = feedparser.parse(text)
        latency_ms = (time.monotonic() - started) * 1000
        bozo = bool(parsed.bozo)
        entry_count = len(parsed.entries)
        if entry_count == 0 and bozo:
            return _failed(
                f"feedparser bozo, 0 entries (bozo_exception={parsed.bozo_exception!s})",
                started,
            )
        return HealthStatus(
            ok=True,
            latency_ms=latency_ms,
            detail=f"{entry_count} entries parsed" + (" (bozo flag set)" if bozo else ""),
            last_checked=datetime.now(UTC),
        )

    async def _scrape_article(self, url: str) -> list[IntelRecord]:
        cfg = HTTPConfig(response_cap_bytes=FEED_RESPONSE_CAP_BYTES)
        try:
            async with HardenedClient(cfg) as http:
                scraper = scraper_mod.Scraper(http)
                return await scraper.scrape(
                    url,
                    source=f"rss:{self.instance}",
                    source_ref=url,
                    respect_robots=self._respect_robots,
                )
        except (
            url_guard.URLGuardError,
            scraper_mod.RobotsDisallowed,
            scraper_mod.ScraperError,
        ):
            # One bad article shouldn't kill the whole pull.
            return []


# Helpers


async def _fetch_feed(url: str) -> str:
    cfg = HTTPConfig(response_cap_bytes=FEED_RESPONSE_CAP_BYTES)
    async with HardenedClient(cfg) as http:
        resp = await http.get(url)
    if resp.status_code != 200:
        raise IntelProviderError(f"feed fetch failed: HTTP {resp.status_code} for {url}")
    return str(resp.text)


def _entry_text(entry: Mapping[str, Any]) -> str:
    parts: list[str] = []
    title = entry.get("title")
    summary = entry.get("summary")
    if isinstance(title, str):
        parts.append(title)
    if isinstance(summary, str):
        parts.append(summary)
    # `content` can be a list of dicts with `value`.
    content = entry.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                v = item.get("value")
                if isinstance(v, str):
                    parts.append(v)
    raw_html = " ".join(parts)
    if "<" in raw_html and ">" in raw_html:
        return scraper_mod.extract_text_from_html(raw_html)
    return raw_html


def _entry_datetime(entry: Mapping[str, Any]) -> datetime | None:
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if parsed is None:
        return None
    try:
        year, month, day, hour, minute, second = (
            parsed[0],
            parsed[1],
            parsed[2],
            parsed[3],
            parsed[4],
            parsed[5],
        )
        return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except (TypeError, ValueError, IndexError):
        return None


def _failed(detail: str, started: float) -> HealthStatus:
    return HealthStatus(
        ok=False,
        latency_ms=(time.monotonic() - started) * 1000,
        detail=detail,
        last_checked=datetime.now(UTC),
    )
