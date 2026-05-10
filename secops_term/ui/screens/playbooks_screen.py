"""Playbooks screen — list playbooks and dry-run them.

Per brief v3 §6.4 + §6.7. The screen is intentionally read-only-ish:
operators can dry-run a playbook to inspect rendered parameters, but
real execution (with side effects: notify dispatch, retro-hunt
enqueue) happens via the CLI ``secops-term playbooks run`` so the
operator-confirmation path stays explicit.

Bindings:

- ``r``      Refresh the playbook list.
- ``d``      Dry-run the highlighted playbook (no side effects).
- ``escape`` Back to nav.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from secops_term.core import audit, paths
from secops_term.playbooks import (
    Engine,
    Playbook,
    build_default_runners,
    list_playbooks,
    load_playbook_file,
    playbooks_root,
)
from secops_term.playbooks.loader import PlaybookError


class PlaybooksScreen(Screen[None]):
    """Browse playbooks; dry-run from inside the TUI."""

    SCREEN_TITLE: ClassVar[str] = "Playbooks"

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("r", "refresh", "Refresh"),
        Binding("d", "dry_run", "Dry-run"),
        Binding("escape", "back", "Back"),
    ]

    DEFAULT_CSS = """
    PlaybooksScreen #pb-status { margin: 1 1 0 1; color: $text-muted; }
    PlaybooksScreen DataTable { height: 1fr; margin: 0 1; }
    PlaybooksScreen #pb-detail {
        height: 14;
        margin: 1;
        padding: 1;
        border: round $accent;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._files: list[Path] = []
        self._playbooks: dict[str, Playbook] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static(
                "Press [bold]r[/] to refresh, [bold]d[/] to dry-run.",
                id="pb-status",
            )
            yield DataTable[str](id="pb-table", zebra_stripes=True)
            yield Static("(select a row to see details)", id="pb-detail")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#pb-table", DataTable)
        table.add_columns("Name", "Trigger", "Steps", "Description")
        table.cursor_type = "row"
        self._refresh()

    def action_refresh(self) -> None:
        self._refresh()

    def action_back(self) -> None:
        self.dismiss()

    async def action_dry_run(self) -> None:
        table = self.query_one("#pb-table", DataTable)
        cur = table.cursor_row
        if cur is None or cur < 0 or cur >= len(self._files):
            self._set_status("[yellow]Highlight a playbook first.[/]")
            return
        path = self._files[cur]
        name = path.stem
        pb = self._playbooks.get(name)
        if pb is None:
            self._set_status(f"[red]No parsed playbook for {name}[/]")
            return

        self._set_status(f"[dim]Dry-running [bold]{name}[/]...[/]")
        paths.ensure_root_initialized()
        engine = Engine(
            runners=build_default_runners(),
            audit_logger=audit.AuditLogger(),
            dry_run=True,
        )
        run = await engine.run(pb, ioc={})

        lines: list[str] = [
            f"[bold]{name}[/] [dim](dry-run)[/]",
            f"overall: {'[green]ok[/]' if run.overall_ok else '[red]failed[/]'}  "
            f"latency: {run.total_latency_ms:.1f}ms",
            "",
        ]
        for s in run.steps:
            if s.skipped:
                marker = "[yellow]skipped[/]"
            elif s.ok:
                marker = "[green]ok[/]"
            else:
                marker = "[red]failed[/]"
            lines.append(f"  - {s.step_id} ({s.type}) {marker}")
            if s.error:
                lines.append(f"      error: {s.error}")
        self.query_one("#pb-detail", Static).update("\n".join(lines))
        self._set_status("[green]Dry-run complete.[/] Use the CLI to run for real.")

    def _refresh(self) -> None:
        self._files = list_playbooks()
        self._playbooks = {}
        table = self.query_one("#pb-table", DataTable)
        table.clear()
        if not self._files:
            self.query_one("#pb-detail", Static).update(
                f"[yellow]No playbooks in {playbooks_root()}.[/]\n"
                "Run `secops-term playbooks init` to install the bundled examples."
            )
            self._set_status("0 playbooks")
            return
        ok = 0
        bad = 0
        for path in self._files:
            try:
                pb = load_playbook_file(path)
            except PlaybookError as exc:
                bad += 1
                table.add_row(
                    path.stem,
                    "[red]ERROR[/]",
                    "-",
                    f"{type(exc).__name__}: {exc}",
                )
                continue
            self._playbooks[path.stem] = pb
            ok += 1
            desc = (pb.description or "").strip().replace("\n", " ")
            table.add_row(path.stem, pb.trigger.type, str(len(pb.steps)), desc[:60])
        self._set_status(f"{ok} ok, {bad} invalid · 'r' refresh · 'd' dry-run · esc back")

    def _set_status(self, msg: str) -> None:
        self.query_one("#pb-status", Static).update(msg)


__all__ = ["PlaybooksScreen"]
