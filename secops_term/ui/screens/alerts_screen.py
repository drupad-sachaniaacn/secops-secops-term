"""Alerts screen — list / detail view across Chronicle, V1, DS.

Per brief v3 §6.3. Phase 3.3 implementation:

- DataTable shows the most recent ingested alerts (newest first).
- Selecting a row populates the detail panel with severity, source,
  entities, and any source-specific raw fields.
- ``r`` triggers a fresh ingest (Chronicle + V1 + DS, deduped).
- ``g`` toggles between raw and grouped view (per brief §6.3 grouping).
- ``escape`` returns to the previous screen.
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from secops_term.alerts.ingest import IngestResult, ingest_all
from secops_term.alerts.types import Alert, AlertGroup


class AlertsScreen(Screen[None]):
    """Unified alerts browser."""

    SCREEN_TITLE: ClassVar[str] = "Alerts"

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("r", "refresh", "Refresh"),
        Binding("g", "toggle_group", "Toggle group"),
        Binding("escape", "back", "Back"),
    ]

    DEFAULT_CSS = """
    AlertsScreen #alerts-status { margin: 1 1 0 1; color: $text-muted; }
    AlertsScreen #alerts-detail {
        height: 14;
        padding: 1;
        border: round $accent;
        margin: 1;
    }
    AlertsScreen DataTable { height: 1fr; margin: 0 1; }
    """

    def __init__(self) -> None:
        super().__init__()
        self._result: IngestResult | None = None
        self._grouped = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static(
                "Press [bold]r[/] to ingest from configured sources.",
                id="alerts-status",
            )
            yield DataTable(id="alerts-table", zebra_stripes=True)
            yield Static(
                "(select a row to see details)",
                id="alerts-detail",
            )
        yield Footer()

    def on_mount(self) -> None:
        self._init_columns()

    def _init_columns(self) -> None:
        table = self.query_one("#alerts-table", DataTable)
        table.clear(columns=True)
        if self._grouped:
            table.add_columns("Count", "Source", "Severity", "Title", "Primary", "Latest")
        else:
            table.add_columns("Source", "Severity", "Detected", "Title", "Entities")
        table.cursor_type = "row"

    async def action_refresh(self) -> None:
        status = self.query_one("#alerts-status", Static)
        status.update("Ingesting from configured sources...")
        try:
            self._result = await ingest_all()
        except Exception as exc:
            status.update(f"[red]Ingest failed:[/] {type(exc).__name__}: {exc}")
            return
        self._render_table()

    def action_toggle_group(self) -> None:
        self._grouped = not self._grouped
        self._init_columns()
        self._render_table()

    def action_back(self) -> None:
        self.dismiss()

    def _render_table(self) -> None:
        table = self.query_one("#alerts-table", DataTable)
        table.clear()
        status = self.query_one("#alerts-status", Static)
        if self._result is None:
            status.update("Press [bold]r[/] to ingest from configured sources.")
            return
        if self._grouped:
            self._render_grouped(table)
        else:
            self._render_raw(table)
        per_source_summary = " · ".join(
            f"{s.source}={'err' if s.error else len(s.alerts)}" for s in self._result.per_source
        )
        status.update(
            f"{len(self._result.alerts)} alert(s) "
            f"({len(self._result.groups)} groups) - {per_source_summary} - "
            f"'r' refresh · 'g' toggle group · esc back"
        )

    def _render_raw(self, table: DataTable[str]) -> None:
        if self._result is None:
            return
        for i, a in enumerate(self._result.alerts[:500]):
            entity_str = ", ".join(f"{e.type}:{e.value}" for e in a.entities[:3])
            table.add_row(
                a.source,
                a.severity,
                a.detected_at.strftime("%Y-%m-%d %H:%M"),
                a.title[:80],
                entity_str[:80],
                key=f"raw-{i}",
            )

    def _render_grouped(self, table: DataTable[str]) -> None:
        if self._result is None:
            return
        for i, g in enumerate(self._result.groups[:500]):
            primary = g.representative.primary_entity()
            primary_str = f"{primary.type}:{primary.value}" if primary is not None else "-"
            table.add_row(
                str(g.count),
                g.representative.source,
                g.representative.severity,
                g.representative.title[:80],
                primary_str[:40],
                g.representative.detected_at.strftime("%Y-%m-%d %H:%M"),
                key=f"group-{i}",
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if self._result is None or event.row_key is None or event.row_key.value is None:
            return
        key = event.row_key.value
        if key.startswith("raw-"):
            try:
                idx = int(key[len("raw-") :])
            except ValueError:
                return
            if 0 <= idx < len(self._result.alerts):
                self._render_alert_detail(self._result.alerts[idx])
        elif key.startswith("group-"):
            try:
                idx = int(key[len("group-") :])
            except ValueError:
                return
            if 0 <= idx < len(self._result.groups):
                self._render_group_detail(self._result.groups[idx])

    def _render_alert_detail(self, alert: Alert) -> None:
        lines = [
            f"[bold]{alert.title}[/]",
            f"source: {alert.source}",
            f"severity: {alert.severity}",
            f"detected: {alert.detected_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"id: {alert.id}",
            f"dedupe_key: {alert.dedupe_key}",
            "entities:",
        ]
        if alert.entities:
            for e in alert.entities[:20]:
                lines.append(f"  - {e.type}: {e.value}")
        else:
            lines.append("  (none)")
        self.query_one("#alerts-detail", Static).update("\n".join(lines))

    def _render_group_detail(self, group: AlertGroup) -> None:
        lines = [
            f"[bold]Group of {group.count}[/] - {group.representative.title}",
            f"source: {group.representative.source}",
            f"severity: {group.representative.severity}",
            "members:",
        ]
        for m in group.members[:20]:
            lines.append(f"  - {m.detected_at.strftime('%Y-%m-%d %H:%M')} {m.id}")
        if len(group.members) > 20:
            lines.append(f"  ... and {len(group.members) - 20} more")
        self.query_one("#alerts-detail", Static).update("\n".join(lines))


__all__ = ["AlertsScreen"]
