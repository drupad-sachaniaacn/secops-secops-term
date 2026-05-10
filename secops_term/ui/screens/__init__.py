"""Top-level Textual screens — one per nav item.

All six phases are complete as of v0.6.0:

- DashboardScreen → Phase 6.5 (summary cards: IOC counts, hunt queue, config)
- IntelScreen → Phase 1
- AlertsScreen → Phase 3
- RetroHuntsScreen → Phase 2
- PlaybooksScreen → Phase 5
- QueryScreen → Phase 4
- ConfigScreen → Phase 6.5 (provider roster + live health checks)
- AuditScreen → Phase 6.5 (audit log viewer + chain verification)
"""

from __future__ import annotations

from textual.screen import Screen

from secops_term.ui.screens.alerts_screen import AlertsScreen
from secops_term.ui.screens.audit_screen import AuditScreen
from secops_term.ui.screens.config_screen import ConfigScreen
from secops_term.ui.screens.dashboard_screen import DashboardScreen
from secops_term.ui.screens.intel_screen import IntelScreen
from secops_term.ui.screens.playbooks_screen import PlaybooksScreen
from secops_term.ui.screens.query_screen import QueryScreen
from secops_term.ui.screens.retro_hunts_screen import RetroHuntsScreen

SCREEN_BY_KEY: dict[str, type[Screen[None]]] = {
    "d": DashboardScreen,
    "i": IntelScreen,
    "a": AlertsScreen,
    "h": RetroHuntsScreen,
    "p": PlaybooksScreen,
    "q": QueryScreen,
    "c": ConfigScreen,
    "l": AuditScreen,
}


__all__ = [
    "SCREEN_BY_KEY",
    "AlertsScreen",
    "AuditScreen",
    "ConfigScreen",
    "DashboardScreen",
    "IntelScreen",
    "PlaybooksScreen",
    "QueryScreen",
    "RetroHuntsScreen",
]
