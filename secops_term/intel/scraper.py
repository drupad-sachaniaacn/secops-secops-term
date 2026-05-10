"""Web scraping + IOC extraction pipeline.

Per brief v3 §6.1: provider-agnostic. Used by the ``rss`` provider for
HTML article-body extraction beyond the feed summary, and by anything
else that needs to pull IOCs out of a remote document.

Pipeline:

1. Validate the URL via :mod:`secops_term.core.url_guard` (SSRF guard).
2. Optionally consult ``robots.txt`` (default on; per-source override
   requires explicit caller opt-in via ``respect_robots=False``, and the
   bypass is logged to the audit chain when an audit logger is wired in).
3. Fetch via :class:`HardenedClient` (TLS verified, body-cap, retry budget).
4. Extract visible text from HTML via ``selectolax`` or from PDF via
   ``pypdf`` (optional dep — degrades gracefully if not installed).
5. Run :func:`extract_iocs_from_text`: refang the text, run ``iocextract``
   per-type extractors, normalize via :func:`secops_term.intel.ioc.normalize_value`,
   capture ±200-char context.
6. Return :class:`IntelRecord` per IOC.

PDF support
-----------
Install the optional ``[pdf]`` extra to enable PDF IOC extraction::

    pip install "secops-term[pdf]"

Without ``pypdf`` installed, PDF responses return an empty IOC list with
an audit event noting the missing dependency.
"""

from __future__ import annotations

import contextlib
import re
import time
import urllib.robotparser
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import iocextract
import selectolax.parser as slx

from secops_term.core import audit as audit_mod
from secops_term.core import url_guard
from secops_term.core.http import HardenedClient
from secops_term.intel import ioc as ioc_mod
from secops_term.intel.providers.base import IntelRecord

_SNIPPET_RADIUS = 200
_DEFAULT_USER_AGENT = "secops-term/0.1"
_DEFAULT_ROBOTS_TTL_S = 3600.0
_HTML_TAGS_TO_STRIP = ("script", "style", "noscript", "nav", "footer", "header", "aside")

# Case-insensitive CVE pattern; iocextract has no CVE extractor of its own.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Word-boundaried email pattern. We don't use ``iocextract.extract_emails``
# because it's greedy with leading whitespace ("Contact attacker@x.com" ends
# up as a single match) — our own regex is stricter and matches what
# ``_canonical_email`` will accept downstream.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}\b")


class ScraperError(Exception):
    """Base class for scraper errors."""


class RobotsDisallowed(ScraperError):
    """``robots.txt`` disallows the requested URL for our user agent."""


@dataclass(frozen=True)
class ExtractedIOC:
    """An IOC found in text, with provenance metadata.

    ``raw`` is whatever string ``iocextract`` matched. ``value`` is the
    canonical form (post-normalization). ``context`` is up to
    ``±_SNIPPET_RADIUS`` chars surrounding the first occurrence in the
    refanged text.
    """

    type: str
    value: str
    raw: str
    context: str


# Text → IOCs


def extract_iocs_from_text(text: str) -> list[ExtractedIOC]:
    """Find every IOC in ``text``. Returns deduplicated, normalized matches.

    Refangs the input first so ``hxxp://evil[.]com`` and
    ``http://evil.com`` produce a single result. Skips standalone-domain
    extraction — ``iocextract.extract_domains`` is too noisy for free-text
    intel; domains enter the corpus via URL hosts and explicit provider
    typing instead.
    """
    if not text:
        return []
    refanged = ioc_mod.refang(text)
    seen: set[tuple[str, str]] = set()
    out: list[ExtractedIOC] = []

    def add(type_: str, raw: str) -> None:
        try:
            canonical = ioc_mod.normalize_value(type_, raw)
        except ValueError:
            return
        key = (type_, canonical)
        if key in seen:
            return
        seen.add(key)
        out.append(
            ExtractedIOC(
                type=type_,
                value=canonical,
                raw=raw,
                context=_extract_snippet(refanged, raw),
            )
        )

    extractors: list[tuple[str, Callable[[str], Any]]] = [
        ("ipv4", iocextract.extract_ipv4s),
        ("ipv6", iocextract.extract_ipv6s),
        ("url", iocextract.extract_urls),
        ("md5", iocextract.extract_md5_hashes),
        ("sha1", iocextract.extract_sha1_hashes),
        ("sha256", iocextract.extract_sha256_hashes),
    ]
    for type_, extractor in extractors:
        try:
            for raw in extractor(refanged):
                add(type_, str(raw))
        except Exception:  # noqa: S112 - one provider failing must not stop the rest
            continue

    for match in _EMAIL_RE.finditer(refanged):
        add("email", match.group(0))

    for match in _CVE_RE.finditer(refanged):
        add("cve", match.group(0))

    return out


def _extract_snippet(text: str, value: str) -> str:
    """Return up to ±_SNIPPET_RADIUS chars around the first occurrence of ``value``."""
    if not value:
        return ""
    idx = text.find(value)
    if idx < 0:
        idx = text.lower().find(value.lower())
    if idx < 0:
        return ""
    start = max(0, idx - _SNIPPET_RADIUS)
    end = min(len(text), idx + len(value) + _SNIPPET_RADIUS)
    return text[start:end]


# HTML → text


def extract_text_from_html(html: str) -> str:
    """Extract visible text from HTML.

    Strips ``<script>`` / ``<style>`` / ``<noscript>`` and obvious
    chrome elements (``nav``, ``footer``, ``header``, ``aside``) before
    pulling the body's text content.
    """
    if not html or not html.strip():
        return ""
    tree = slx.HTMLParser(html)
    for selector in _HTML_TAGS_TO_STRIP:
        for node in tree.css(selector):
            node.decompose()
    body = tree.body
    if body is None:
        # Malformed HTML — fall back to root text.
        root = tree.root
        if root is None:
            return ""
        return str(root.text(separator=" ", strip=True))
    return str(body.text(separator=" ", strip=True))


def extract_text_from_pdf(raw_bytes: bytes) -> str:
    """Extract plain text from a PDF document using ``pypdf``.

    Returns an empty string when:

    - ``raw_bytes`` is empty.
    - ``pypdf`` is not installed (install the ``[pdf]`` optional extra).
    - The PDF cannot be parsed (encrypted, malformed, scan-only, etc.).

    Raises nothing — callers should treat an empty result as "no text
    extractable from this PDF", not as an error.
    """
    if not raw_bytes:
        return ""
    try:
        import io

        import pypdf
    except ImportError:
        return ""
    try:
        reader = pypdf.PdfReader(io.BytesIO(raw_bytes))
        parts: list[str] = []
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                parts.append(page_text)
        return "\n".join(parts)
    except Exception:
        return ""


# robots.txt


class RobotsChecker:
    """Per-origin ``robots.txt`` cache backed by stdlib ``RobotFileParser``.

    Decisions:

    - HTTP 200 → parse as published.
    - HTTP non-200 (404, 5xx, etc.) → treat as no rules (allow everything).
      Industry convention; we never crawl, only fetch on user request.
    - Network error → same treatment as non-200.

    A small race exists where two concurrent ``allowed()`` calls for the
    same origin may fetch ``robots.txt`` twice; that is harmless (last
    writer wins, both produce identical state).
    """

    def __init__(
        self,
        http: HardenedClient,
        *,
        user_agent: str = _DEFAULT_USER_AGENT,
        ttl_s: float = _DEFAULT_ROBOTS_TTL_S,
    ) -> None:
        self._http = http
        self._ua = user_agent
        self._ttl_s = ttl_s
        self._cache: dict[str, tuple[float, urllib.robotparser.RobotFileParser]] = {}

    @property
    def user_agent(self) -> str:
        return self._ua

    async def allowed(self, url: str) -> bool:
        parts = urlsplit(url)
        if not parts.scheme or not parts.netloc:
            return True
        origin = f"{parts.scheme}://{parts.netloc}"
        rp = await self._get_rp(origin)
        return bool(rp.can_fetch(self._ua, url))

    async def _get_rp(self, origin: str) -> urllib.robotparser.RobotFileParser:
        now = time.monotonic()
        cached = self._cache.get(origin)
        if cached is not None and now - cached[0] < self._ttl_s:
            return cached[1]
        rp = urllib.robotparser.RobotFileParser()
        try:
            resp = await self._http.get(f"{origin}/robots.txt")
            if resp.status_code == 200:
                rp.parse(resp.text.splitlines())
            else:
                rp.parse([])  # non-200 → no rules → allow all
        except Exception:
            # Any fetch error (network, retry-budget, etc.) → allow.
            # robots.txt being unreachable shouldn't break a user-initiated fetch.
            rp.parse([])
        self._cache[origin] = (time.monotonic(), rp)
        return rp


# Scraper orchestrator


class Scraper:
    """Fetch a URL, extract IOCs, return :class:`IntelRecord` rows.

    Wires the SSRF guard, hardened HTTP client, ``robots.txt`` checker,
    HTML text extraction, and ``iocextract`` pipeline together.
    """

    def __init__(
        self,
        http: HardenedClient,
        *,
        robots: RobotsChecker | None = None,
        audit_logger: audit_mod.AuditLogger | None = None,
        user_agent: str = _DEFAULT_USER_AGENT,
    ) -> None:
        self._http = http
        self._robots = robots if robots is not None else RobotsChecker(http, user_agent=user_agent)
        self._audit = audit_logger
        self._ua = user_agent

    @property
    def robots(self) -> RobotsChecker:
        return self._robots

    async def scrape(
        self,
        url: str,
        *,
        source: str,
        source_ref: str | None = None,
        respect_robots: bool = True,
        max_response_bytes: int | None = None,
    ) -> list[IntelRecord]:
        """Fetch ``url`` and return the IOCs found in its body.

        - ``source`` is the ``provider:instance`` label baked into each
          ``IntelRecord``.
        - ``source_ref`` defaults to ``url`` and is what gets stored in
          ``ioc_sources.source_ref``.
        - ``respect_robots=False`` skips the ``robots.txt`` check; the bypass
          is recorded as an audit entry when an audit logger is configured.
        - ``max_response_bytes`` overrides the HTTP client's response cap
          for this request only.
        """
        # 1. SSRF guard. Raises url_guard.URLGuardError on a forbidden URL.
        url_guard.validate_url(url)

        # 2. robots.txt
        if not respect_robots:
            self._audit_event(
                "scraper.robots_bypassed",
                {"url": url, "source": source},
            )
        else:
            allowed = await self._robots.allowed(url)
            if not allowed:
                self._audit_event(
                    "scraper.robots_disallowed",
                    {"url": url, "source": source},
                )
                raise RobotsDisallowed(f"robots.txt disallows {url}")

        # 3. Fetch
        kwargs: dict[str, Any] = {}
        if max_response_bytes is not None:
            kwargs["response_cap_bytes"] = max_response_bytes
        resp = await self._http.get(url, **kwargs)
        if resp.status_code >= 400:
            raise ScraperError(f"fetch failed: HTTP {resp.status_code} for {url}")

        # 4. Extract text
        content_type = resp.headers.get("Content-Type", "").lower()
        body_text: str
        if "pdf" in content_type:
            body_text = extract_text_from_pdf(resp.content)
            if not body_text:
                self._audit_event(
                    "scraper.pdf_no_text",
                    {
                        "url": url,
                        "source": source,
                        "hint": "pypdf not installed or PDF has no extractable text",
                    },
                )
        elif "html" in content_type:
            body_text = extract_text_from_html(resp.text)
        else:
            body_text = resp.text

        # 5. Extract IOCs
        fetched_at = datetime.now(UTC)
        records: list[IntelRecord] = []
        for match in extract_iocs_from_text(body_text):
            records.append(
                IntelRecord(
                    source=source,
                    type=match.type,
                    value=match.value,
                    fetched_at=fetched_at,
                    context=match.context,
                    source_ref=source_ref if source_ref is not None else url,
                )
            )

        self._audit_event(
            "scraper.fetched",
            {"url": url, "source": source, "ioc_count": len(records)},
        )
        return records

    def _audit_event(self, event: str, data: dict[str, Any]) -> None:
        if self._audit is None:
            return
        entry: dict[str, Any] = {"kind": "scraper", "event": event}
        entry.update(data)
        # Audit failures must never break the scrape.
        with contextlib.suppress(Exception):
            self._audit.emit(entry)


__all__ = [
    "ExtractedIOC",
    "RobotsChecker",
    "RobotsDisallowed",
    "Scraper",
    "ScraperError",
    "extract_iocs_from_text",
    "extract_text_from_html",
    "extract_text_from_pdf",
]
