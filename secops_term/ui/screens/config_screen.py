"""Config screen — provider roster and live health checks.

Phase 6.5 implementation:

- DataTable shows every configured intel provider instance.
- ``t`` runs health checks on all enabled instances and updates the table.
- ``r`` refreshes the config-file view without re-running health checks.
- Selecting a row populates the detail panel.
- ``escape`` returns to the previous screen.
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from secops_term.core import config_io
from secops_term.core.registry import NotRegistered


class ConfigScreen(Screen[None]):
    """Intel provider configuration and health dashboard."""

    SCREEN_TITLE: ClassVar[str] = "Config"

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("t", "test_all", "Test all"),
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "back", "Back"),
    ]

    DEFAULT_CSS = """
    ConfigScreen #cfg-status { margin: 1 1 0 1; color: $text-muted; }
    ConfigScreen #cfg-detail {
        height: 8;
        padding: 1;
        border: round $accent;
        margin: 1;
    }
    ConfigScreen DataTable { height: 1fr; margin: 0 1; }
    """

    # Each tuple: (provider, instance, enabled, status, latency_ms, detail)
    _TableRow = tuple[str, str, str, str, str, str]

    def __init__(self) -> None:
        super().__init__()
        self._rows: list[ConfigScreen._TableRow] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static(
                "Press [bold]t[/] to run health checks on all configured providers.",
                id="cfg-status",
            )
            yield DataTable(id="cfg-table", zebra_stripes=True)
            yield Static("(select a row to see details)", id="cfg-detail")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#cfg-table", DataTable)
        table.add_columns("Provider", "Instance", "Enabled", "Status", "Latency", "Detail")
        table.cursor_type = "row"
        self._load_config()

    def action_refresh(self) -> None:
        self._load_config()

    async def action_test_all(self) -> None:
        from secops_term.intel import providers as providers_mod

        providers_mod.discover()

        status_w = self.query_one("#cfg-status", Static)
        status_w.update("Running health checks…")
        try:
            cfg = config_io.load_config()
        except Exception as exc:
            status_w.update(f"[red]Failed to load config:[/] {exc}")
            return

        intel_providers = cfg.get("intel_providers", {})
        ok_count = 0
        fail_count = 0

        updated: list[ConfigScreen._TableRow] = []
        for provider_name, instances in intel_providers.items():
            if not isinstance(instances, dict):
                continue
            for inst_name, inst_cfg in instances.items():
                enabled_bool = bool(
                    inst_cfg.get("enabled", True) if isinstance(inst_cfg, dict) else True
                )
                enabled_str = "✓" if enabled_bool else "✗"
                if not enabled_bool:
                    updated.append((provider_name, inst_name, enabled_str, "—", "—", "disabled"))
                    continue
                try:
                    try:
                        provider_cls = providers_mod.PROVIDERS.get(provider_name)
                    except NotRegistered:
                        updated.append(
                            (
                                provider_name,
                                inst_name,
                                enabled_str,
                                "[yellow]?[/]",
                                "—",
                                "not registered",
                            )
                        )
                        fail_count += 1
                        continue
                    cfg_dict = inst_cfg if isinstance(inst_cfg, dict) else {}
                    provider = provider_cls.from_config(inst_name, cfg_dict)
                    health = await provider.health_check()
                    status_text = "[green]OK[/]" if health.ok else "[red]FAIL[/]"
                    latency_text = f"{health.latency_ms:.0f} ms"
                    detail_text = (health.detail or "")[:80]
                    updated.append(
                        (
                            provider_name,
                            inst_name,
                            enabled_str,
                            status_text,
                            latency_text,
                            detail_text,
                        )
                    )
                    if health.ok:
                        ok_count += 1
                    else:
                        fail_count += 1
                except Exception as exc:
                    updated.append(
                        (provider_name, inst_name, enabled_str, "[red]ERR[/]", "—", str(exc)[:80])
                    )
                    fail_count += 1

        self._rows = updated
        self._render_table()
        status_w.update(
            f"Health check complete: [green]{ok_count} OK[/], [red]{fail_count} FAIL[/].  "
            "Press [bold]t[/] to retest · [bold]r[/] refresh · [bold]esc[/] back"
        )

    def action_back(self) -> None:
        self.dismiss()

    def _load_config(self) -> None:
        try:
            cfg = config_io.load_config()
        except Exception as exc:
            self.query_one("#cfg-status", Static).update(f"[red]Config error:[/] {exc}")
            return

        intel_providers = cfg.get("intel_providers", {})
        self._rows = []

        if not isinstance(intel_providers, dict) or not intel_providers:
            self.query_one("#cfg-status", Static).update(
                "No intel providers configured. "
                "Run [bold]secops-term config intel PROVIDER[/] to add one."
            )
            self._render_table()
            return

        for provider_name, instances in intel_providers.items():
            if not isinstance(instances, dict):
                continue
            for inst_name, inst_cfg in instances.items():
                enabled_bool = bool(
                    inst_cfg.get("enabled", True) if isinstance(inst_cfg, dict) else True
                )
                enabled_str = "✓" if enabled_bool else "✗"
                self._rows.append((provider_name, inst_name, enabled_str, "—", "—", ""))

        count = len(self._rows)
        self.query_one("#cfg-status", Static).update(
            f"{count} provider instance(s) configured.  "
            "Press [bold]t[/] to test all · [bold]r[/] refresh · [bold]esc[/] back"
        )
        self._render_table()

    def _render_table(self) -> None:
        table = self.query_one("#cfg-table", DataTable)
        table.clear()
        for i, (provider, instance, enabled, status, latency, detail) in enumerate(self._rows):
            table.add_row(provider, instance, enabled, status, latency, detail, key=f"cfg-{i}")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        key = event.row_key.value
        if not key.startswith("cfg-"):
            return
        try:
            idx = int(key[len("cfg-") :])
        except ValueError:
            return
        if not (0 <= idx < len(self._rows)):
            return
        provider, instance, enabled, status, latency, detail = self._rows[idx]
        lines = [
            f"[bold]{provider}[/] / {instance}",
            f"  Enabled : {enabled}",
            f"  Status  : {status}",
            f"  Latency : {latency}",
            f"  Detail  : {detail or '(press t to run health check)'}",
        ]
        self.query_one("#cfg-detail", Static).update("\n".join(lines))


__all__ = ["ConfigScreen"]
