"""Textual application root — Phase 0 shell with 8 stubbed nav screens.

Per brief v3 §5: nav items in the footer are bound to single keys
(``d/i/a/h/p/q/c/l``). Each key pushes the matching screen. Real UI lands
in subsequent phases.
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.widgets import Footer, Header, Static

from secops_term.ui.screens import SCREEN_BY_KEY


class SecOpsTermApp(App[None]):
    """SecOps Terminal — main Textual app."""

    CSS = """
    #welcome { padding: 2 4; }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("d", "go('d')", "Dashboard"),
        Binding("i", "go('i')", "Intel"),
        Binding("a", "go('a')", "Alerts"),
        Binding("h", "go('h')", "Retro Hunts"),
        Binding("p", "go('p')", "Playbooks"),
        Binding("q", "go('q')", "Query Helper"),
        Binding("c", "go('c')", "Config"),
        Binding("l", "go('l')", "Audit Log"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "[bold]SecOps Terminal[/] — Phase 0 shell.\n\n"
            "Press one of the nav keys in the footer to switch screens, or "
            "Ctrl+Q to quit.",
            id="welcome",
        )
        yield Footer()

    async def action_go(self, key: str) -> None:
        screen_cls = SCREEN_BY_KEY.get(key)
        if screen_cls is None:
            return
        await self.push_screen(screen_cls())


def run() -> None:
    """Entry point used by ``secops-term tui``."""
    SecOpsTermApp().run()


__all__ = ["SecOpsTermApp", "run"]
