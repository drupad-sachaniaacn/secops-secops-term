"""Threat Intel screen — list / filter / search / detail view.

Per brief v3 §6.1. Phase 1 implementation:

- DataTable shows the most recent IOCs from the SQLite store.
- Search input filters by substring (LIKE-escaped via ``IOCStore.search``).
- Selecting a row populates the detail panel with the IOC's metadata and
  every source observation (``ioc_sources``).
- ``r`` refreshes; ``/`` focuses search; ``escape`` returns to the
  previous screen.
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Static

from secops_term.intel import store as store_mod


class IntelScreen(Screen[None]):
    """Threat-intel browser."""

    SCREEN_TITLE: ClassVar[str] = "Threat Intel"

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("slash", "focus_search", "Search"),
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "back", "Back"),
    ]

    DEFAULT_CSS = """
    IntelScreen #intel-search { margin: 1 1 0 1; }
    IntelScreen #intel-count { margin: 0 1; color: $text-muted; }
    IntelScreen #intel-detail {
        height: 12;
        padding: 1;
        border: round $accent;
        margin: 1;
    }
    IntelScreen DataTable { height: 1fr; margin: 0 1; }
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
            yield Input(
                placeholder="Search IOC value... (press / to focus)",
                id="intel-search",
            )
            yield Static("Loading...", id="intel-count")
            yield DataTable(id="intel-table", zebra_stripes=True)
            yield Static(
                "(select a row to see sources)",
                id="intel-detail",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#intel-table", DataTable)
        table.add_columns("Type", "Value", "Last Seen", "Sources")
        table.cursor_type = "row"
        self._refresh()

    def _refresh(self, query: str = "") -> None:
        store = self._get_store()
        table = self.query_one("#intel-table", DataTable)
        table.clear()
        if query.strip():
            iocs = store.search(query, limit=500)
        else:
            iocs = store.find(limit=500)
        for ioc in iocs:
            try:
                source_count = len(store.sources_for(ioc.id))
            except Exception:
                source_count = 0
            table.add_row(
                ioc.type,
                ioc.value[:80],
                ioc.last_seen.strftime("%Y-%m-%d %H:%M"),
                str(source_count),
                key=str(ioc.id),
            )
        count_widget = self.query_one("#intel-count", Static)
        count_widget.update(f"{len(iocs)} IOC(s) — '/' search · 'r' refresh · esc back")

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "intel-search":
            self._refresh(event.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        try:
            ioc_id = int(event.row_key.value)
        except ValueError:
            return
        store = self._get_store()
        ioc = store.get_by_id(ioc_id)
        if ioc is None:
            return
        sources = store.sources_for(ioc.id)
        lines: list[str] = [
            f"[bold]{ioc.type}[/] {ioc.value}",
            f"first_seen: {ioc.first_seen.strftime('%Y-%m-%d %H:%M')}",
            f"last_seen: {ioc.last_seen.strftime('%Y-%m-%d %H:%M')}",
            f"confidence: {ioc.confidence if ioc.confidence is not None else '-'}",
            f"tags: {', '.join(ioc.tags) if ioc.tags else '-'}",
            f"sources ({len(sources)}):",
        ]
        for s in sources[:20]:
            lines.append(
                f"  - {s.source} | {s.source_ref or '-'} | "
                f"{s.fetched_at.strftime('%Y-%m-%d %H:%M')}"
            )
        if len(sources) > 20:
            lines.append(f"  ... and {len(sources) - 20} more")
        self.query_one("#intel-detail", Static).update("\n".join(lines))

    def action_focus_search(self) -> None:
        self.query_one("#intel-search", Input).focus()

    def action_refresh(self) -> None:
        query = self.query_one("#intel-search", Input).value
        self._refresh(query)

    def action_back(self) -> None:
        self.dismiss()


__all__ = ["IntelScreen"]
