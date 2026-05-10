"""Dashboard screen — at-a-glance summary of IOC store, hunts, and config.

Phase 6.5 implementation:

- Static-panel layout with IOC counts by type, retro-hunt job counts by
  status, and configured provider summary.
- ``r`` refreshes all counters.
- ``escape`` returns to the previous screen.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from secops_term.core import config_io
from secops_term.intel import store as store_mod

# Ordered for display.
_IOC_TYPES = (
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "sha256",
    "sha1",
    "md5",
    "email",
    "cve",
)
_HUNT_STATUSES = ("queued", "running", "done", "error")


class DashboardScreen(Screen[None]):
    """At-a-glance dashboard for SecOps Terminal."""

    SCREEN_TITLE: ClassVar[str] = "Dashboard"

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "back", "Back"),
    ]

    DEFAULT_CSS = """
    DashboardScreen #dash-body {
        margin: 1 2;
        height: 1fr;
        overflow-y: auto;
    }
    DashboardScreen #dash-status {
        margin: 1 2 0 2;
        color: $text-muted;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="dash-status")
        yield Static("", id="dash-body")
        yield Footer()

    def on_mount(self) -> None:
        self._load()

    def action_refresh(self) -> None:
        self._load()

    def action_back(self) -> None:
        self.dismiss()

    def _load(self) -> None:
        status_w = self.query_one("#dash-status", Static)
        body_w = self.query_one("#dash-body", Static)
        status_w.update("Loading…")
        try:
            summary = _build_summary()
        except Exception as exc:
            body_w.update(f"[red]Error loading dashboard:[/] {exc}")
            status_w.update("")
            return
        body_w.update(summary)
        status_w.update(
            f"Updated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC  "
            "│  [bold]r[/] refresh · [bold]esc[/] back"
        )


def _build_summary() -> str:
    lines: list[str] = []

    # ── Intel store ────────────────────────────────────────────────────────
    lines.append("[bold]┌─ Intel Store ─────────────────────────┐[/]")
    store = store_mod.get_default_store()
    try:
        total = store.count()
        lines.append(f"  Total IOCs      : [bold]{total:>8,}[/]")
        for ioc_type in _IOC_TYPES:
            n = store.count(type_=ioc_type)
            label = f"{ioc_type:<14}"
            lines.append(f"  {label}: {n:>8,}")

        # Last IOC observed timestamp.
        recent = store.find(limit=1)
        if recent:
            last_ts = recent[0].last_seen.strftime("%Y-%m-%d %H:%M UTC")
            lines.append(f"  Last seen       : {last_ts}")
    finally:
        store.database.close()
    lines.append("")

    # ── Retro hunt queue ───────────────────────────────────────────────────
    lines.append("[bold]┌─ Retro Hunt Queue ────────────────────┐[/]")
    store2 = store_mod.get_default_store()
    try:
        all_jobs = store2.recent_jobs(limit=10_000)
        status_counts: dict[str, int] = {s: 0 for s in _HUNT_STATUSES}
        for job in all_jobs:
            if job.status in status_counts:
                status_counts[job.status] += 1
        for s in _HUNT_STATUSES:
            color_map = {
                "queued": "yellow",
                "running": "cyan",
                "done": "green",
                "error": "red",
            }
            color = color_map.get(s, "white")
            lines.append(f"  {s:<14}: [{color}]{status_counts[s]:>8,}[/]")
    finally:
        store2.database.close()
    lines.append("")

    # ── Configuration ──────────────────────────────────────────────────────
    lines.append("[bold]┌─ Configuration ───────────────────────┐[/]")
    try:
        cfg = config_io.load_config()
        intel_cfg = cfg.get("intel_providers", {})
        provider_names = sorted(intel_cfg.keys()) if isinstance(intel_cfg, dict) else []
        instance_count = (
            sum(len(v) for v in intel_cfg.values() if isinstance(v, dict))
            if isinstance(intel_cfg, dict)
            else 0
        )
        lines.append(f"  Providers       : {len(provider_names):>8,}")
        lines.append(f"  Instances       : {instance_count:>8,}")
        if provider_names:
            lines.append(f"  Names           : {', '.join(provider_names[:6])}")
        notifiers = cfg.get("notifiers", {})
        notifier_count = len(notifiers) if isinstance(notifiers, dict) else 0
        lines.append(f"  Notifiers       : {notifier_count:>8,}")
        chronicle_cfg = cfg.get("chronicle", {})
        v1_cfg = cfg.get("vision_one", {})
        lines.append(f"  Chronicle       : {'configured' if chronicle_cfg else 'not set'}")
        lines.append(f"  Vision One      : {'configured' if v1_cfg else 'not set'}")
    except Exception as exc:
        lines.append(f"  [yellow](config unavailable: {exc})[/]")

    lines.append("")
    lines.append("[dim]Press [bold]c[/] to open full config view · [bold]l[/] for audit log[/]")
    return "\n".join(lines)


__all__ = ["DashboardScreen"]
