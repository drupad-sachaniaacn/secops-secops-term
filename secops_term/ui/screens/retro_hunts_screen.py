"""Retro Hunts screen — list / detail view for retro_hunt_jobs.

Per brief v3 §6.2. Phase 2.3 implementation:

- DataTable shows the most recent retro-hunt jobs (newest first).
- Selecting a row populates the detail panel with the IOC, query,
  hits/error, and timestamps.
- ``r`` refreshes; ``escape`` returns to the previous screen.

A worker that drains the ``queued`` jobs runs out-of-band via
``secops-term hunt run``; this screen is read-only.
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from secops_term.intel import store as store_mod


class RetroHuntsScreen(Screen[None]):
    """Retro-hunt job browser."""

    SCREEN_TITLE: ClassVar[str] = "Retro Hunts"

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "back", "Back"),
    ]

    DEFAULT_CSS = """
    RetroHuntsScreen #rh-count { margin: 1 1 0 1; color: $text-muted; }
    RetroHuntsScreen #rh-detail {
        height: 12;
        padding: 1;
        border: round $accent;
        margin: 1;
    }
    RetroHuntsScreen DataTable { height: 1fr; margin: 0 1; }
    """

    def __init__(self, store: store_mod.IOCStore | None = None) -> None:
        super().__init__()
        self._store: store_mod.IOCStore | None = store

    def _get_store(self) -> store_mod.IOCStore:
        if self._store is None:
            self._store = store_mod.get_default_store()
        return self._store

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("Loading...", id="rh-count")
            yield DataTable(id="rh-table", zebra_stripes=True)
            yield Static(
                "(select a row to see details)",
                id="rh-detail",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#rh-table", DataTable)
        table.add_columns("ID", "Status", "Platform", "Type", "Value", "Hits", "Created")
        table.cursor_type = "row"
        self._refresh()

    def _refresh(self) -> None:
        store = self._get_store()
        try:
            jobs = store.recent_jobs(limit=200)
        except Exception:
            jobs = []
        table = self.query_one("#rh-table", DataTable)
        table.clear()
        for job in jobs:
            try:
                ioc = store.get_by_id(job.ioc_id)
            except Exception:
                ioc = None
            ioc_type = ioc.type if ioc is not None else "-"
            ioc_value = ioc.value[:50] if ioc is not None else "-"
            hits_str = str(job.hits) if job.hits is not None else "-"
            table.add_row(
                str(job.id),
                job.status,
                job.platform,
                ioc_type,
                ioc_value,
                hits_str,
                job.created_at.strftime("%Y-%m-%d %H:%M"),
                key=str(job.id),
            )
        self.query_one("#rh-count", Static).update(f"{len(jobs)} job(s) - 'r' refresh - esc back")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        try:
            job_id = int(event.row_key.value)
        except ValueError:
            return
        store = self._get_store()
        job = store.get_job(job_id)
        if job is None:
            return
        try:
            ioc = store.get_by_id(job.ioc_id)
        except Exception:
            ioc = None
        lines: list[str] = [
            f"[bold]Job {job.id}[/] - {job.status}",
            f"platform: {job.platform}",
            f"created: {job.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
        ]
        if job.completed_at is not None:
            lines.append(f"completed: {job.completed_at.strftime('%Y-%m-%d %H:%M:%S')}")
        if ioc is not None:
            lines.append(f"ioc: {ioc.type} {ioc.value}")
        else:
            lines.append(f"ioc: id={job.ioc_id} (deleted)")
        if job.hits is not None:
            lines.append(f"hits: {job.hits}")
        if job.query:
            lines.append(f"query: {job.query}")
        if job.error:
            lines.append(f"error: {job.error}")
        self.query_one("#rh-detail", Static).update("\n".join(lines))

    def action_refresh(self) -> None:
        self._refresh()

    def action_back(self) -> None:
        self.dismiss()


__all__ = ["RetroHuntsScreen"]
