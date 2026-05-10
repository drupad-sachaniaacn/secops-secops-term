"""Audit log screen — scrollable, verifiable hash-chained log viewer.

Phase 6.5 implementation:

- DataTable shows the most recent audit entries (newest first, capped at 500).
- Selecting a row populates the detail panel with the full JSON entry.
- ``v`` triggers an offline chain verification across all audit files.
- ``r`` refreshes from disk.
- ``escape`` returns to the previous screen.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from secops_term.core import audit as audit_mod
from secops_term.core import paths


class AuditScreen(Screen[None]):
    """Audit log browser with hash-chain verification."""

    SCREEN_TITLE: ClassVar[str] = "Audit Log"

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("v", "verify", "Verify chain"),
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "back", "Back"),
    ]

    DEFAULT_CSS = """
    AuditScreen #audit-status { margin: 1 1 0 1; color: $text-muted; }
    AuditScreen #audit-detail {
        height: 10;
        padding: 1;
        border: round $accent;
        margin: 1;
    }
    AuditScreen DataTable { height: 1fr; margin: 0 1; }
    """

    def __init__(self) -> None:
        super().__init__()
        # List of (seq, ts, kind, summary, full_json_str) for rows
        self._entries: list[tuple[str, str, str, str, str]] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("Loading audit log...", id="audit-status")
            yield DataTable(id="audit-table", zebra_stripes=True)
            yield Static("(select a row to see details)", id="audit-detail")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#audit-table", DataTable)
        table.add_columns("Seq", "Timestamp", "Kind", "Summary")
        table.cursor_type = "row"
        self._load()

    def action_refresh(self) -> None:
        self._load()

    async def action_verify(self) -> None:
        status = self.query_one("#audit-status", Static)
        status.update("[yellow]Verifying hash chain…[/]")
        try:
            files_checked, entries_checked = audit_mod.verify_chain()
        except audit_mod.ChainBroken as exc:
            status.update(f"[red bold]Chain broken![/] {exc}")
            return
        except Exception as exc:
            status.update(f"[red]Verification error:[/] {exc}")
            return
        status.update(
            f"[green]Chain OK[/] — {files_checked} file(s), {entries_checked:,} entr(ies) verified."
        )

    def action_back(self) -> None:
        self.dismiss()

    def _load(self) -> None:
        self._entries.clear()
        root = paths.get_root()
        try:
            all_files = _ordered_audit_files(root)
        except Exception as exc:
            self.query_one("#audit-status", Static).update(
                f"[red]Could not read audit root:[/] {exc}"
            )
            return

        if not all_files:
            self.query_one("#audit-status", Static).update(
                "No audit log found. Entries will appear here after first command."
            )
            return

        raw: list[audit_mod.AuditEntry] = []
        read_errors = 0
        for path in all_files:
            try:
                for entry in audit_mod._iter_entries(path):
                    raw.append(entry)
            except Exception:
                read_errors += 1

        # Show newest first; cap at 500 rows for performance.
        raw.sort(key=lambda e: e.seq, reverse=True)
        for ae in raw[:500]:
            kind = str(ae.entry.get("kind", ""))
            summary = _entry_summary(ae.entry)
            ts_short = ae.ts[:19].replace("T", " ")
            full = json.dumps(ae.entry, indent=2, ensure_ascii=False)
            self._entries.append((str(ae.seq), ts_short, kind, summary, full))

        self._render_table()
        total = len(raw)
        showing = min(500, total)
        warn = f" [yellow]({read_errors} file(s) unreadable)[/]" if read_errors else ""
        self.query_one("#audit-status", Static).update(
            f"{total:,} entr(ies) — showing {showing}.{warn}  "
            f"[bold]v[/] verify chain · [bold]r[/] refresh · [bold]esc[/] back"
        )

    def _render_table(self) -> None:
        table = self.query_one("#audit-table", DataTable)
        table.clear()
        for i, (seq, ts, kind, summary, _full) in enumerate(self._entries):
            table.add_row(seq, ts, kind, summary, key=f"row-{i}")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        key = event.row_key.value
        if not key.startswith("row-"):
            return
        try:
            idx = int(key[len("row-") :])
        except ValueError:
            return
        if 0 <= idx < len(self._entries):
            _seq, ts, kind, summary, full = self._entries[idx]
            lines = [
                f"[bold]seq=[/]{_seq}  [bold]ts=[/]{ts}  [bold]kind=[/]{kind or '(none)'}",
                summary,
                "",
                full[:2000],  # cap at 2000 chars for display
            ]
            self.query_one("#audit-detail", Static).update("\n".join(lines))


def _ordered_audit_files(root: Path) -> list[Path]:
    """List rotated audit-*.jsonl files chronologically, then the active file."""
    rotated = sorted(root.glob("audit-*.jsonl"))
    active = root / "audit.jsonl"
    out: list[Path] = list(rotated)
    if active.exists():
        out.append(active)
    return out


def _entry_summary(entry: dict[str, object]) -> str:
    """Build a one-line summary string from an audit entry dict."""
    parts: list[str] = []
    for key in ("event", "action", "command", "url", "path", "source", "kind"):
        val = entry.get(key)
        if val and key != "kind":
            parts.append(str(val)[:80])
            break
    # Add numeric context fields.
    for key in ("ioc_count", "hits", "seq"):
        val = entry.get(key)
        if val is not None:
            parts.append(f"{key}={val}")
    return "  ".join(parts)[:120] if parts else json.dumps(entry, ensure_ascii=False)[:120]


__all__ = ["AuditScreen"]
