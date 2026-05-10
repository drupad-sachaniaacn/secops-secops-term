"""Scraper: text→IOC, html→text, robots.txt, full pipeline."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx

from secops_term.core import audit as audit_mod
from secops_term.core import url_guard
from secops_term.core.http import HardenedClient, HTTPConfig
from secops_term.intel import scraper as scraper_mod

# extract_iocs_from_text


def test_extract_ipv4() -> None:
    text = "We saw 8.8.8.8 and also 1.1.1.1 in the logs."
    iocs = scraper_mod.extract_iocs_from_text(text)
    types = {(i.type, i.value) for i in iocs}
    assert ("ipv4", "8.8.8.8") in types
    assert ("ipv4", "1.1.1.1") in types


def test_extract_url() -> None:
    iocs = scraper_mod.extract_iocs_from_text(
        "Visit https://evil.example.com/payload for the goods."
    )
    urls = [i.value for i in iocs if i.type == "url"]
    assert "https://evil.example.com/payload" in urls


def test_extract_defanged_url() -> None:
    iocs = scraper_mod.extract_iocs_from_text("C2: hxxps://evil[.]example[.]com/c2")
    urls = [i.value for i in iocs if i.type == "url"]
    assert "https://evil.example.com/c2" in urls


def test_extract_defanged_ipv4() -> None:
    iocs = scraper_mod.extract_iocs_from_text("Source: 8[.]8[.]8[.]8 traffic")
    ipv4s = [i.value for i in iocs if i.type == "ipv4"]
    assert "8.8.8.8" in ipv4s


def test_extract_email() -> None:
    iocs = scraper_mod.extract_iocs_from_text("Contact attacker@evil.example.com immediately.")
    emails = [i.value for i in iocs if i.type == "email"]
    assert "attacker@evil.example.com" in emails


def test_extract_sha256() -> None:
    h = "a" * 64
    iocs = scraper_mod.extract_iocs_from_text(f"Sample hash: {h}")
    sha256s = [i.value for i in iocs if i.type == "sha256"]
    assert h in sha256s


def test_extract_md5_and_sha1() -> None:
    md5 = "d" * 32
    sha1 = "e" * 40
    iocs = scraper_mod.extract_iocs_from_text(f"md5={md5} sha1={sha1}")
    md5s = [i.value for i in iocs if i.type == "md5"]
    sha1s = [i.value for i in iocs if i.type == "sha1"]
    assert md5 in md5s
    assert sha1 in sha1s


def test_extract_cve_uppercase() -> None:
    iocs = scraper_mod.extract_iocs_from_text("Patched in fix for CVE-2024-12345 last week.")
    cves = [i.value for i in iocs if i.type == "cve"]
    assert "CVE-2024-12345" in cves


def test_extract_cve_lowercase() -> None:
    iocs = scraper_mod.extract_iocs_from_text("Bug cve-2024-99999 active.")
    cves = [i.value for i in iocs if i.type == "cve"]
    assert "CVE-2024-99999" in cves


def test_extract_dedupes_within_same_text() -> None:
    text = "Sample 8.8.8.8 again 8.8.8.8 yet again 8.8.8.8."
    iocs = scraper_mod.extract_iocs_from_text(text)
    ipv4_count = sum(1 for i in iocs if i.type == "ipv4" and i.value == "8.8.8.8")
    assert ipv4_count == 1


def test_extract_collapses_defanged_and_canonical() -> None:
    text = "Both forms: 8.8.8.8 and 8[.]8[.]8[.]8."
    iocs = scraper_mod.extract_iocs_from_text(text)
    ipv4_count = sum(1 for i in iocs if i.type == "ipv4" and i.value == "8.8.8.8")
    assert ipv4_count == 1


def test_extract_empty_text_returns_empty() -> None:
    assert scraper_mod.extract_iocs_from_text("") == []
    assert scraper_mod.extract_iocs_from_text("   \n\n  ") == []


def test_extract_no_iocs_returns_empty() -> None:
    text = "This is a benign sentence. Nothing to see here."
    assert scraper_mod.extract_iocs_from_text(text) == []


def test_extract_snippet_present_for_short_text() -> None:
    iocs = scraper_mod.extract_iocs_from_text("see 8.8.8.8 here")
    assert iocs[0].context == "see 8.8.8.8 here"


def test_extract_snippet_truncated_for_long_text() -> None:
    long_lead = "x" * 500
    long_tail = "y" * 500
    text = f"{long_lead} 8.8.8.8 {long_tail}"
    iocs = scraper_mod.extract_iocs_from_text(text)
    snippet = iocs[0].context
    # ±200 chars of context around the value.
    assert "8.8.8.8" in snippet
    assert len(snippet) <= 2 * 200 + len("8.8.8.8") + 2  # +2 for the spaces


def test_extract_skips_invalid_values() -> None:
    # iocextract may match 256.0.0.1 syntactically but normalize_value
    # rejects it; the scraper should drop it silently.
    iocs = scraper_mod.extract_iocs_from_text("Bogus: 256.0.0.1 here")
    assert all(not (i.type == "ipv4" and i.value == "256.0.0.1") for i in iocs)


# extract_text_from_html


def test_html_extracts_visible_text() -> None:
    html = "<html><body><p>Hello <b>world</b>!</p></body></html>"
    out = scraper_mod.extract_text_from_html(html)
    assert "Hello" in out
    assert "world" in out


def test_html_strips_script_content() -> None:
    html = "<html><body><script>alert(8.8.8.8)</script><p>Real content</p></body></html>"
    out = scraper_mod.extract_text_from_html(html)
    assert "Real content" in out
    assert "alert" not in out
    assert "8.8.8.8" not in out


def test_html_strips_style_content() -> None:
    html = "<html><body><style>.x { color: red; 8.8.8.8 }</style><p>Body</p></body></html>"
    out = scraper_mod.extract_text_from_html(html)
    assert "Body" in out
    assert "color: red" not in out


def test_html_strips_chrome() -> None:
    html = (
        "<html><body>"
        "<nav>menu menu menu</nav>"
        "<header>top stuff</header>"
        "<main><p>Article body</p></main>"
        "<aside>side links</aside>"
        "<footer>copyright</footer>"
        "</body></html>"
    )
    out = scraper_mod.extract_text_from_html(html)
    assert "Article body" in out
    assert "menu" not in out
    assert "side links" not in out
    assert "copyright" not in out


def test_html_empty_returns_empty() -> None:
    assert scraper_mod.extract_text_from_html("") == ""
    assert scraper_mod.extract_text_from_html("   ") == ""


def test_html_malformed_does_not_crash() -> None:
    # Selectolax tolerates malformed HTML; we just need a defined string back.
    out = scraper_mod.extract_text_from_html("<html<body>oops")
    assert isinstance(out, str)


# RobotsChecker


@pytest.fixture
def respx_router() -> Iterator[respx.Router]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``url_guard._resolve_all`` return a fake public IP for any host."""
    monkeypatch.setattr(
        url_guard,
        "_resolve_all",
        lambda host, port: [("93.184.216.34", socket.AF_INET)],
    )


async def test_robots_no_robots_file_allows(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://example.com/robots.txt").mock(return_value=httpx.Response(404))
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        rc = scraper_mod.RobotsChecker(http)
        assert await rc.allowed("https://example.com/anything") is True


async def test_robots_disallows_specific_path(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://example.com/robots.txt").mock(
        return_value=httpx.Response(
            200,
            text="User-agent: *\nDisallow: /private/\n",
            headers={"Content-Type": "text/plain"},
        )
    )
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        rc = scraper_mod.RobotsChecker(http)
        assert await rc.allowed("https://example.com/private/secret") is False
        assert await rc.allowed("https://example.com/public/ok") is True


async def test_robots_caches_result(respx_router: respx.Router) -> None:
    route = respx_router.get("https://example.com/robots.txt").mock(
        return_value=httpx.Response(200, text="User-agent: *\nDisallow:\n")
    )
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        rc = scraper_mod.RobotsChecker(http)
        await rc.allowed("https://example.com/a")
        await rc.allowed("https://example.com/b")
        await rc.allowed("https://example.com/c")
    # Cached after the first fetch.
    assert route.call_count == 1


async def test_robots_network_error_falls_through_to_allow(
    respx_router: respx.Router,
) -> None:
    respx_router.get("https://example.com/robots.txt").mock(
        side_effect=httpx.ConnectError("simulated")
    )
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        rc = scraper_mod.RobotsChecker(http)
        assert await rc.allowed("https://example.com/anything") is True


# Scraper full pipeline


async def test_scraper_full_pipeline(respx_router: respx.Router, fake_dns: None) -> None:
    respx_router.get("https://example.com/robots.txt").mock(return_value=httpx.Response(404))
    respx_router.get("https://example.com/article").mock(
        return_value=httpx.Response(
            200,
            text=(
                "<html><body><p>Threat report: hxxps://evil[.]example[.]com/c2 "
                "and IP 8.8.8.8 plus CVE-2024-1111.</p></body></html>"
            ),
            headers={"Content-Type": "text/html"},
        )
    )
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        scraper = scraper_mod.Scraper(http)
        records = await scraper.scrape("https://example.com/article", source="rss:test")
    types = {(r.type, r.value) for r in records}
    assert ("ipv4", "8.8.8.8") in types
    assert ("url", "https://evil.example.com/c2") in types
    assert ("cve", "CVE-2024-1111") in types
    assert all(r.source == "rss:test" for r in records)
    assert all(r.source_ref == "https://example.com/article" for r in records)


async def test_scraper_uses_source_ref_when_provided(
    respx_router: respx.Router, fake_dns: None
) -> None:
    respx_router.get("https://example.com/robots.txt").mock(return_value=httpx.Response(404))
    respx_router.get("https://example.com/article").mock(
        return_value=httpx.Response(
            200, text="IP 8.8.8.8 here", headers={"Content-Type": "text/plain"}
        )
    )
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        scraper = scraper_mod.Scraper(http)
        records = await scraper.scrape(
            "https://example.com/article",
            source="rss:test",
            source_ref="custom-ref",
        )
    assert all(r.source_ref == "custom-ref" for r in records)


async def test_scraper_rejects_private_url() -> None:
    """No ``fake_dns`` here — the IP literal must hit the real loopback check."""
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        scraper = scraper_mod.Scraper(http)
        with pytest.raises(url_guard.PrivateAddress):
            await scraper.scrape("https://127.0.0.1/", source="rss:test")


async def test_scraper_blocks_when_robots_disallows(
    respx_router: respx.Router, fake_dns: None
) -> None:
    respx_router.get("https://example.com/robots.txt").mock(
        return_value=httpx.Response(
            200,
            text="User-agent: *\nDisallow: /\n",
        )
    )
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        scraper = scraper_mod.Scraper(http)
        with pytest.raises(scraper_mod.RobotsDisallowed):
            await scraper.scrape("https://example.com/article", source="rss:test")


async def test_scraper_bypass_robots_with_opt_in(
    respx_router: respx.Router, fake_dns: None, tmp_root: Path
) -> None:
    """`respect_robots=False` skips the check AND emits an audit entry."""
    respx_router.get("https://example.com/article").mock(
        return_value=httpx.Response(200, text="IP 8.8.8.8", headers={"Content-Type": "text/plain"})
    )
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        scraper = scraper_mod.Scraper(http, audit_logger=log)
        records = await scraper.scrape(
            "https://example.com/article",
            source="rss:test",
            respect_robots=False,
        )
    assert any(r.value == "8.8.8.8" for r in records)
    text = (tmp_root / "audit.jsonl").read_text(encoding="utf-8")
    assert "scraper.robots_bypassed" in text


async def test_scraper_emits_audit_on_disallow(
    respx_router: respx.Router, fake_dns: None, tmp_root: Path
) -> None:
    respx_router.get("https://example.com/robots.txt").mock(
        return_value=httpx.Response(200, text="User-agent: *\nDisallow: /\n")
    )
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        scraper = scraper_mod.Scraper(http, audit_logger=log)
        with pytest.raises(scraper_mod.RobotsDisallowed):
            await scraper.scrape("https://example.com/article", source="rss:test")
    text = (tmp_root / "audit.jsonl").read_text(encoding="utf-8")
    assert "scraper.robots_disallowed" in text


async def test_scraper_emits_fetched_audit_event(
    respx_router: respx.Router, fake_dns: None, tmp_root: Path
) -> None:
    respx_router.get("https://example.com/robots.txt").mock(return_value=httpx.Response(404))
    respx_router.get("https://example.com/article").mock(
        return_value=httpx.Response(200, text="IP 8.8.8.8", headers={"Content-Type": "text/plain"})
    )
    log = audit_mod.AuditLogger(path=tmp_root / "audit.jsonl")
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        scraper = scraper_mod.Scraper(http, audit_logger=log)
        await scraper.scrape("https://example.com/article", source="rss:test")
    text = (tmp_root / "audit.jsonl").read_text(encoding="utf-8")
    assert "scraper.fetched" in text


async def test_scraper_raises_on_4xx(respx_router: respx.Router, fake_dns: None) -> None:
    respx_router.get("https://example.com/robots.txt").mock(return_value=httpx.Response(404))
    respx_router.get("https://example.com/article").mock(return_value=httpx.Response(404))
    async with HardenedClient(HTTPConfig(max_retries=1)) as http:
        scraper = scraper_mod.Scraper(http)
        with pytest.raises(scraper_mod.ScraperError):
            await scraper.scrape("https://example.com/article", source="rss:test")
