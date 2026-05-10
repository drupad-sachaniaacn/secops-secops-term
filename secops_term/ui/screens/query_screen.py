"""NLP Query Helper screen — natural language → UDM / TMV1 query.

Per brief v3 §6.5: review-then-execute. The screen NEVER auto-pushes
the generated query to Chronicle / Vision One; the operator copies it
manually after review.

Bindings:

- ``r``      Generate (run the AI bridge against the current question).
- ``t``      Toggle target (UDM ↔ TMV1).
- ``c``      Copy current query to clipboard via pyperclip (best-effort).
- ``escape`` Back to nav.
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Input, Static

from secops_term.ai.audit import AuditingBridge
from secops_term.ai.bridge import ClaudeNotFound
from secops_term.ai.clipboard import ClipboardBridge
from secops_term.ai.nlp_prompts import QueryTarget
from secops_term.ai.nlp_query import generate_query
from secops_term.ai.selector import (
    NoTransportAvailable,
    TransportCandidate,
    compose_bridge,
)
from secops_term.core import audit, paths


class QueryScreen(Screen[None]):
    """NLP → query screen, review-then-execute."""

    SCREEN_TITLE: ClassVar[str] = "NLP Query Helper"

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("r", "generate", "Generate"),
        Binding("t", "toggle_target", "Toggle target"),
        Binding("c", "copy", "Copy query"),
        Binding("escape", "back", "Back"),
    ]

    DEFAULT_CSS = """
    QueryScreen #query-status { margin: 1 1 0 1; color: $text-muted; }
    QueryScreen #query-input { margin: 1; }
    QueryScreen #query-output {
        height: 8;
        margin: 1;
        padding: 1;
        border: round $accent;
    }
    QueryScreen #query-validation {
        height: 6;
        margin: 0 1;
        padding: 1;
        border: round $warning;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._target: QueryTarget = "udm"
        self._last_query: str = ""

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static(
                f"Target: [bold]{self._target.upper()}[/]  "
                "Type your SOC question, then press [bold]r[/].",
                id="query-status",
            )
            yield Input(
                placeholder="e.g. all DNS queries to evil.com in last 24h",
                id="query-input",
            )
            yield Static("(no query yet)", id="query-output")
            yield Static("", id="query-validation")
        yield Footer()

    def _set_status(self, msg: str) -> None:
        self.query_one("#query-status", Static).update(msg)

    def action_toggle_target(self) -> None:
        self._target = "tmv1" if self._target == "udm" else "udm"
        self._set_status(
            f"Target: [bold]{self._target.upper()}[/]  "
            "Type your SOC question, then press [bold]r[/]."
        )

    def action_back(self) -> None:
        self.dismiss()

    def action_copy(self) -> None:
        if not self._last_query:
            self._set_status("[yellow]Nothing to copy yet.[/]")
            return
        try:
            import pyperclip  # type: ignore[import-not-found,import-untyped,unused-ignore]

            pyperclip.copy(self._last_query)
            self._set_status("[green]Query copied to clipboard.[/]")
        except Exception as exc:
            self._set_status(f"[red]Copy failed: {type(exc).__name__}: {exc}[/]")

    async def action_generate(self) -> None:
        question = self.query_one("#query-input", Input).value.strip()
        if not question:
            self._set_status("[yellow]Type a question first.[/]")
            return
        self._set_status(f"[dim]Calling AI bridge for {self._target.upper()}...[/]")

        try:
            bridge = await self._build_bridge()
        except NoTransportAvailable as exc:
            self._set_status(f"[red]No AI transport available:[/] {exc}")
            return
        try:
            result = await generate_query(bridge, target=self._target, question=question)
        except Exception as exc:
            self._set_status(f"[red]Bridge failed:[/] {type(exc).__name__}: {exc}")
            return

        self._last_query = result.query
        self.query_one("#query-output", Static).update(
            f"[bold]Generated query[/] (transport: {bridge.transport}):\n\n"
            + (result.query or "[i](empty response)[/]")
        )

        validation_lines: list[str] = []
        if result.validation.errors:
            validation_lines.append("[red bold]Errors:[/]")
            for e in result.validation.errors:
                validation_lines.append(f"  - {e}")
        if result.validation.warnings:
            validation_lines.append("[yellow bold]Warnings:[/]")
            for w in result.validation.warnings:
                validation_lines.append(f"  - {w}")
        if not validation_lines:
            validation_lines.append("[green]Validation: ok[/]")
        validation_lines.append(
            "\n[bold yellow]Review before running.[/] Copy with [bold]c[/]; never auto-executed."
        )
        self.query_one("#query-validation", Static).update("\n".join(validation_lines))
        self._set_status(
            f"[green]Done.[/] Target: [bold]{self._target.upper()}[/]  "
            "Press [bold]r[/] to regenerate, [bold]t[/] to toggle target."
        )

    async def _build_bridge(self) -> AuditingBridge:
        from secops_term.ai.bridge import HeadlessClaudeBridge, resolve_claude_path

        paths.ensure_root_initialized()
        audit_logger = audit.AuditLogger()
        candidates: list[TransportCandidate] = []
        try:
            path = resolve_claude_path()
            candidates.append(
                TransportCandidate(HeadlessClaudeBridge(claude_path=path), "claude-headless")
            )
        except ClaudeNotFound:
            pass

        async def _no_response_provider(_msg: str) -> str:
            # In the TUI, clipboard fallback isn't really viable without a
            # paste-modal. For Phase 4 we surface a clear error rather
            # than silently hanging on stdin.
            raise NoTransportAvailable(
                "clipboard transport requires a paste-modal in the TUI; "
                "use the CLI `secops-term ai query` for clipboard fallback"
            )

        candidates.append(
            TransportCandidate(
                ClipboardBridge(response_provider=_no_response_provider),
                "clipboard",
            )
        )
        return await compose_bridge(candidates, audit_logger=audit_logger)


__all__ = ["QueryScreen"]
