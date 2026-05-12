"""Typer CLI entry point.

Phase 0 + Phase 1 surface:

- ``secops-term version``           — print package version.
- ``secops-term tui``               — launch the Textual app.
- ``secops-term doctor``            — run all Phase 0 health checks.
- ``secops-term audit verify``      — walk the hash-chained audit log.
- ``secops-term config``            — interactive config wizard.
- ``secops-term config show``       — display config.toml + keyring summary (masked).
- ``secops-term config chronicle``  — configure Chronicle (scaffolding).
- ``secops-term config vision-one`` — configure Vision One (scaffolding).
- ``secops-term config intel``      — configure an intel provider+instance.
- ``secops-term config test``       — health-check a single provider+instance.
- ``secops-term config test-all``   — health-check every configured provider+instance.
- ``secops-term config rotate``     — placeholder.
- ``secops-term intel pull``        — pull from configured intel providers.
- ``secops-term intel list``        — list IOCs from the local store.
- ``secops-term ai query``          — NLP → UDM / TMV1 query (review-then-execute).
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime
from typing import Any

# Windows cp1252 terminals can't render Unicode box-drawing / arrow characters
# that Rich uses in help text and tables.  Force UTF-8 output before any import
# of rich or typer so the codec is set before their first write.
if sys.platform == "win32" and os.environ.get("PYTHONUTF8") != "1":
    os.environ["PYTHONUTF8"] = "1"
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import typer
from rich.console import Console
from rich.table import Table

from secops_term import __version__
from secops_term.ai import (
    AIBridgeError,
    HeadlessClaudeBridge,
    NoTransportAvailable,
    TransportCandidate,
    compose_bridge,
    generate_query,
    resolve_claude_path,
)
from secops_term.ai.bridge import ClaudeNotFound
from secops_term.ai.clipboard import ClipboardBridge
from secops_term.ai.nlp_prompts import QueryTarget
from secops_term.alerts import ingest as alerts_ingest
from secops_term.chronicle import factory as chronicle_factory
from secops_term.chronicle.client import ChronicleError
from secops_term.chronicle.retro_hunt import (
    CHRONICLE_PLATFORM,
    RetroHuntWorker,
)
from secops_term.core import audit, config_io, doctor, health, paths, secrets
from secops_term.core.registry import NotRegistered
from secops_term.intel import orchestrator
from secops_term.intel import store as store_mod
from secops_term.intel.providers import PROVIDERS
from secops_term.trendmicro import factory as tm_factory
from secops_term.trendmicro.deep_security import DeepSecurityError
from secops_term.trendmicro.vision_one import VisionOneError

app = typer.Typer(
    name="secops-term",
    help="Navigational TUI for SOC engineers. Sits between SIEM and SOAR.",
    no_args_is_help=True,
    add_completion=False,
)

config_app = typer.Typer(
    help="Configure providers, notifiers, and run health checks.",
    invoke_without_command=True,
)
audit_app = typer.Typer(help="Audit log utilities.")
intel_app = typer.Typer(help="Threat-intel pull / list utilities.")
hunt_app = typer.Typer(help="Retro-hunt: enqueue, drain, status.")
alerts_app = typer.Typer(help="Unified alerts: ingest from Chronicle / V1 / DS.")
ai_app = typer.Typer(help="AI bridge: NLP → query helper, debug utilities.")
playbooks_app = typer.Typer(help="Playbook engine: list / show / run YAML playbooks.")
app.add_typer(config_app, name="config")
app.add_typer(audit_app, name="audit")
app.add_typer(intel_app, name="intel")
app.add_typer(hunt_app, name="hunt")
app.add_typer(alerts_app, name="alerts")
app.add_typer(ai_app, name="ai")
app.add_typer(playbooks_app, name="playbooks")

_console = Console()


# Top-level commands


@app.command()
def version() -> None:
    """Print the installed package version."""
    typer.echo(__version__)


@app.command()
def tui() -> None:
    """Launch the Textual application."""
    # Imported here so importing the CLI doesn't pull Textual into every
    # short-lived invocation (e.g. `secops-term version`).
    from secops_term.app import run as run_tui

    run_tui()


@app.command(name="doctor")
def doctor_cmd() -> None:
    """Run all Phase 0 health checks."""
    results = doctor.run_doctor()
    table = Table(title="SecOps Terminal — Doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")
    for r in results:
        status = "[green]OK[/]" if r.ok else "[red]FAIL[/]"
        table.add_row(r.name, status, r.detail)
    _console.print(table)
    if not doctor.overall_ok(results):
        raise typer.Exit(code=1)


# Audit subcommands


@audit_app.command(name="verify")
def audit_verify() -> None:
    """Walk the audit chain across rotated files. Exits non-zero on chain break."""
    try:
        files, entries = audit.verify_chain()
    except audit.ChainBroken as exc:
        _console.print(f"[red]CHAIN BROKEN[/]: {exc}")
        raise typer.Exit(code=1) from exc
    if files == 0 and entries == 0:
        _console.print(f"[yellow]No audit log found at {paths.get_root()} (nothing to verify)[/]")
        return
    _console.print(f"[green]OK[/]: verified {entries} entries across {files} file(s)")


# Config subcommands


@config_app.callback()
def config_default(ctx: typer.Context) -> None:
    """Interactive wizard if no subcommand is given."""
    if ctx.invoked_subcommand is None:
        _run_wizard()


@config_app.command(name="show")
def config_show() -> None:
    """Display ``config.toml`` and a keyring summary (secrets masked)."""
    path = config_io.config_path()
    if not path.exists():
        _console.print(f"[yellow]No config.toml at {path} — run `secops-term config` to set up[/]")
        return
    try:
        data = config_io.load_config()
    except config_io.ConfigError as exc:
        _console.print(f"[red]Could not parse config: {exc}[/]")
        raise typer.Exit(code=1) from exc
    _console.print(f"[bold]Config[/] ({path}):")
    _print_block(data, depth=0)


def _print_block(data: dict[str, Any], *, depth: int) -> None:
    indent = "  " * depth
    for k, v in data.items():
        if isinstance(v, dict):
            _console.print(f"{indent}[cyan]{k}[/]:")
            _print_block(v, depth=depth + 1)
        else:
            _console.print(f"{indent}{k} = {v!r}")


@config_app.command(name="chronicle")
def config_chronicle() -> None:
    """Configure Chronicle SecOps (Phase 0 scaffolding)."""
    paths.ensure_root_initialized()
    cfg = config_io.load_config()
    chronicle = cfg.setdefault("chronicle", {})
    chronicle["customer_id"] = typer.prompt(
        "Customer ID", default=str(chronicle.get("customer_id", "")) or None
    )
    chronicle["region"] = typer.prompt(
        "Region (us / eu / asia)", default=str(chronicle.get("region", "us"))
    )
    chronicle["allow_write"] = typer.confirm(
        "Enable destructive actions for this profile (allow_write)?",
        default=bool(chronicle.get("allow_write", False)),
    )
    sa_json = typer.prompt(
        "Paste service-account JSON (single line, or leave blank to skip)",
        default="",
        show_default=False,
    )
    if sa_json.strip():
        mgr = secrets.get_manager()
        mgr.set_secret("chronicle", "default", "service_account_json", sa_json.strip())
        _console.print("[green]Stored service-account JSON in keyring.[/]")
    config_io.save_config(cfg)
    _console.print("[green]Saved Chronicle config.[/] Phase 2 wires up the actual API client.")


@config_app.command(name="vision-one")
def config_vision_one() -> None:
    """Configure Trend Micro Vision One (Phase 0 scaffolding)."""
    paths.ensure_root_initialized()
    cfg = config_io.load_config()
    v1 = cfg.setdefault("vision_one", {})
    v1["allow_write"] = typer.confirm(
        "Enable destructive actions for this profile (allow_write)?",
        default=bool(v1.get("allow_write", False)),
    )
    # Per brief §13 the V1 region is locked to US — base URL is hardcoded
    # at api.xdr.trendmicro.com, not configurable.
    token = typer.prompt("API token (leave blank to skip)", default="", show_default=False)
    if token.strip():
        mgr = secrets.get_manager()
        mgr.set_secret("vision_one", "default", "api_token", token.strip())
        _console.print("[green]Stored API token in keyring.[/]")
    config_io.save_config(cfg)
    _console.print("[green]Saved Vision One config.[/] Phase 3 wires up the actual API client.")


@config_app.command(name="intel")
def config_intel(
    provider: str = typer.Argument(..., help="Provider name, e.g. abuse_ch, otx, rss."),
    instance: str = typer.Option("default", "--instance", "-i", help="Per-instance label."),
) -> None:
    """Configure a threat-intel provider (Phase 0 scaffolding)."""
    paths.ensure_root_initialized()
    cfg = config_io.load_config()
    section = (
        cfg.setdefault("intel_providers", {}).setdefault(provider, {}).setdefault(instance, {})
    )
    section["enabled"] = typer.confirm(
        "Enable this provider?",
        default=bool(section.get("enabled", True)),
    )
    token = typer.prompt(
        f"API token for {provider}:{instance} (leave blank to skip)",
        default="",
        show_default=False,
    )
    if token.strip():
        mgr = secrets.get_manager()
        mgr.set_secret(f"intel.{provider}", instance, "api_token", token.strip())
        _console.print(
            f"[green]Stored API token in keyring under "
            f"secops-term:intel.{provider}:{instance}/api_token[/]"
        )
    config_io.save_config(cfg)
    _console.print(
        f"[green]Saved intel provider config: {provider}:{instance}.[/] "
        f"Phase 1 ships the concrete provider modules."
    )


@config_app.command(name="test")
def config_test(
    provider: str = typer.Argument(..., help="Provider name (chronicle, abuse_ch, otx, rss)."),
    instance: str = typer.Option("default", "--instance", "-i"),
) -> None:
    """Health-check one configured provider+instance."""
    target: object | None
    if provider == "chronicle":
        try:
            target = chronicle_factory.build_chronicle_client(instance=instance)
        except ChronicleError as exc:
            _console.print(f"[red]{exc}[/]")
            raise typer.Exit(code=1) from exc
        if target is None:
            _console.print(
                "[yellow]Chronicle not configured (no `[chronicle]` block in "
                "config.toml). Run `secops-term config chronicle`.[/]"
            )
            raise typer.Exit(code=1)
    elif provider == "vision_one":
        try:
            target = tm_factory.build_vision_one_client(instance=instance)
        except VisionOneError as exc:
            _console.print(f"[red]{exc}[/]")
            raise typer.Exit(code=1) from exc
        if target is None:
            _console.print(
                "[yellow]Vision One not configured (no `[vision_one]` block "
                "in config.toml). Run `secops-term config vision-one`.[/]"
            )
            raise typer.Exit(code=1)
    elif provider == "deep_security":
        try:
            target = tm_factory.build_deep_security_client(instance=instance)
        except DeepSecurityError as exc:
            _console.print(f"[red]{exc}[/]")
            raise typer.Exit(code=1) from exc
        if target is None:
            _console.print(
                "[yellow]Deep Security not configured (no `[deep_security]` block "
                "in config.toml). Run `secops-term config deep-security`.[/]"
            )
            raise typer.Exit(code=1)
    else:
        cfg = config_io.load_config()
        intel_cfg = cfg.get("intel_providers") or {}
        inst_cfg = (intel_cfg.get(provider) or {}).get(instance)
        if inst_cfg is None:
            _console.print(
                f"[yellow]No config for {provider}:{instance} in {config_io.config_path()}[/]"
            )
            raise typer.Exit(code=1)
        try:
            cls = PROVIDERS.get(provider)
        except NotRegistered:
            _console.print(f"[red]Provider {provider!r} is not registered.[/]")
            raise typer.Exit(code=1) from None
        try:
            target = cls.from_config(instance, inst_cfg)
        except Exception as exc:
            _console.print(f"[red]from_config failed: {type(exc).__name__}: {exc}[/]")
            raise typer.Exit(code=1) from exc
    row = asyncio.run(health.run_one(target, instance=instance))  # type: ignore[arg-type]
    _print_health_rows([row])
    if not row.status.ok:
        raise typer.Exit(code=1)


@config_app.command(name="test-all")
def config_test_all() -> None:
    """Health-check every configured provider+instance."""
    targets = orchestrator.build_health_targets()
    if not targets:
        _console.print(
            "[yellow]No configured intel providers. "
            "Run `secops-term config intel <provider>` to add one.[/]"
        )
        return
    rows = asyncio.run(health.run_all(targets))
    _print_health_rows(rows)
    if any(not r.status.ok for r in rows):
        raise typer.Exit(code=1)


def _print_health_rows(rows: list[health.HealthRow]) -> None:
    table = Table(title="Health checks")
    table.add_column("Provider")
    table.add_column("Instance")
    table.add_column("Status")
    table.add_column("Latency (ms)")
    table.add_column("Detail")
    for row in rows:
        status = "[green]OK[/]" if row.status.ok else "[red]FAIL[/]"
        table.add_row(
            row.name,
            row.instance or "-",
            status,
            f"{row.status.latency_ms:.1f}",
            row.status.detail,
        )
    _console.print(table)


@config_app.command(name="rotate")
def config_rotate(
    provider: str = typer.Argument(..., help="Provider name to rotate."),
    instance: str = typer.Option("default", "--instance", "-i"),
) -> None:
    """Rotate a single credential (placeholder)."""
    _console.print(
        f"[yellow]Rotation for {provider}:{instance} will land alongside its provider module. "
        f"Use `config <provider>` to overwrite the keyring entry for now.[/]"
    )


# Alerts subcommands


@alerts_app.command(name="list")
def alerts_list(
    source: str | None = typer.Option(
        None,
        "--source",
        help="Filter by source: chronicle / vision_one / deep_security.",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Filter by severity: info / low / medium / high / critical.",
    ),
    since: str | None = typer.Option(
        None, "--since", help="ISO-8601 timestamp; only include alerts after this."
    ),
    limit: int = typer.Option(50, "--limit", "-n", min=1, max=1000),
    grouped: bool = typer.Option(
        False, "--grouped", help="Show grouped near-duplicates rather than raw alerts."
    ),
) -> None:
    """Ingest alerts from configured sources, dedup, and display."""
    since_dt: datetime | None = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError as exc:
            _console.print(f"[red]Invalid --since {since!r}: {exc}[/]")
            raise typer.Exit(code=1) from exc

    result = asyncio.run(alerts_ingest.ingest_all(since=since_dt, limit=limit))

    if not result.per_source:
        _console.print(
            "[yellow]No alert sources configured. "
            "Run `secops-term config chronicle | vision-one | deep-security`.[/]"
        )
        return

    for src in result.per_source:
        if src.error:
            _console.print(f"[red]{src.source}: error[/] {src.error}")
        else:
            _console.print(f"[green]{src.source}: {len(src.alerts)} alert(s) ingested[/]")

    alerts = result.alerts
    if source is not None:
        alerts = [a for a in alerts if a.source == source]
    if severity is not None:
        alerts = [a for a in alerts if a.severity == severity]

    if grouped:
        groups = [g for g in result.groups if (source is None or g.representative.source == source)]
        if severity is not None:
            groups = [g for g in groups if g.representative.severity == severity]
        if not groups:
            _console.print("[yellow](no alert groups)[/]")
            return
        table = Table(title=f"Alert groups ({len(groups)})")
        table.add_column("Count", justify="right")
        table.add_column("Source")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Primary entity")
        table.add_column("Latest")
        for g in groups[:limit]:
            primary = g.representative.primary_entity()
            primary_str = f"{primary.type}:{primary.value}" if primary else "-"
            table.add_row(
                str(g.count),
                g.representative.source,
                g.representative.severity,
                g.representative.title[:60],
                primary_str[:40],
                g.representative.detected_at.strftime("%Y-%m-%d %H:%M"),
            )
        _console.print(table)
        return

    if not alerts:
        _console.print("[yellow](no alerts after filters)[/]")
        return

    table = Table(title=f"Alerts ({len(alerts)})")
    table.add_column("Source")
    table.add_column("Severity")
    table.add_column("Detected")
    table.add_column("Title")
    table.add_column("Entities")
    for a in alerts[:limit]:
        entity_str = ", ".join(f"{e.type}:{e.value}" for e in a.entities[:3])
        table.add_row(
            a.source,
            a.severity,
            a.detected_at.strftime("%Y-%m-%d %H:%M"),
            a.title[:60],
            entity_str[:60],
        )
    _console.print(table)


# Hunt subcommands


@hunt_app.command(name="enqueue")
def hunt_enqueue(
    ioc_id: int = typer.Argument(..., help="IOC id from the local store."),
    platform: str = typer.Option(
        CHRONICLE_PLATFORM,
        "--platform",
        "-p",
        help="Platform name (default: chronicle).",
    ),
) -> None:
    """Enqueue a retro-hunt job for one IOC on one platform."""
    store = store_mod.get_default_store()
    try:
        ioc = store.get_by_id(ioc_id)
        if ioc is None:
            _console.print(f"[red]No IOC with id {ioc_id} in the store.[/]")
            raise typer.Exit(code=1)
        try:
            job_id = store.enqueue_retro_hunt(ioc_id, platform)
        except store_mod.IOCStoreError as exc:
            _console.print(f"[red]{exc}[/]")
            raise typer.Exit(code=1) from exc
        _console.print(
            f"[green]Enqueued job {job_id}[/] for {ioc.type} {ioc.value} on platform={platform!r}"
        )
    finally:
        store.database.close()


@hunt_app.command(name="run")
def hunt_run(
    max_jobs: int = typer.Option(
        50, "--max-jobs", "-n", min=1, help="Drain at most N jobs this run."
    ),
    lookback_hours: int = typer.Option(
        24 * 30,
        "--lookback-hours",
        min=1,
        help="UDM search lookback window (default: 30 days).",
    ),
    limit_per_query: int = typer.Option(1000, "--limit-per-query", min=1, max=10_000),
) -> None:
    """Drain queued Chronicle retro-hunt jobs."""
    try:
        client = chronicle_factory.build_chronicle_client()
    except ChronicleError as exc:
        _console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if client is None:
        _console.print("[yellow]Chronicle not configured. Run `secops-term config chronicle`.[/]")
        raise typer.Exit(code=1)
    store = store_mod.get_default_store()
    try:
        worker = RetroHuntWorker(
            client,
            store,
            lookback_hours=lookback_hours,
            limit_per_query=limit_per_query,
        )
        result = asyncio.run(worker.run_once(max_jobs=max_jobs))
        _console.print(
            f"Drained [bold]{result.drained}[/] job(s): "
            f"[green]{result.succeeded} succeeded[/], "
            f"[red]{result.failed} failed[/], "
            f"[yellow]{result.skipped} skipped[/]"
        )
        if result.failed > 0:
            raise typer.Exit(code=1)
    finally:
        store.database.close()


@hunt_app.command(name="status")
def hunt_status(
    platform: str | None = typer.Option(None, "--platform", "-p", help="Filter by platform."),
    status_filter: str | None = typer.Option(
        None,
        "--status",
        "-s",
        help="Filter by status (queued, running, done, error).",
    ),
    limit: int = typer.Option(50, "--limit", "-n", min=1, max=10_000),
) -> None:
    """Show recent retro-hunt jobs (newest first)."""
    store = store_mod.get_default_store()
    try:
        try:
            jobs = store.recent_jobs(platform=platform, status=status_filter, limit=limit)
        except store_mod.IOCStoreError as exc:
            _console.print(f"[red]{exc}[/]")
            raise typer.Exit(code=1) from exc
        if not jobs:
            _console.print("[yellow](no retro-hunt jobs)[/]")
            return
        table = Table(title=f"Retro-hunt jobs ({len(jobs)})")
        table.add_column("ID", justify="right")
        table.add_column("Status")
        table.add_column("Platform")
        table.add_column("IOC")
        table.add_column("Hits", justify="right")
        table.add_column("Created")
        table.add_column("Error")
        for job in jobs:
            ioc = store.get_by_id(job.ioc_id)
            ioc_str = f"{ioc.type} {ioc.value[:40]}" if ioc else f"<deleted id={job.ioc_id}>"
            hits_str = str(job.hits) if job.hits is not None else "-"
            table.add_row(
                str(job.id),
                job.status,
                job.platform,
                ioc_str,
                hits_str,
                job.created_at.strftime("%Y-%m-%d %H:%M"),
                (job.error or "")[:60],
            )
        _console.print(table)
    finally:
        store.database.close()


# Intel subcommands


@intel_app.command(name="pull")
def intel_pull(
    provider: str | None = typer.Option(
        None, "--provider", "-p", help="Pull only this provider name."
    ),
    instance: str | None = typer.Option(
        None, "--instance", "-i", help="Pull only this instance label."
    ),
    since: str | None = typer.Option(
        None,
        "--since",
        help="ISO-8601 timestamp; only pull entries newer than this.",
    ),
) -> None:
    """Pull IOCs from configured intel providers and upsert into the store."""
    since_dt: datetime | None = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError as exc:
            _console.print(f"[red]Invalid --since {since!r}: {exc}[/]")
            raise typer.Exit(code=1) from exc

    results = orchestrator.pull_all_sync(
        provider_filter=provider,
        instance_filter=instance,
        since=since_dt,
    )
    if not results:
        _console.print(
            "[yellow]No matching configured providers. "
            "Run `secops-term config intel <name>` to add one, "
            "then `secops-term config show` to verify.[/]"
        )
        return

    table = Table(title="Intel pull results")
    table.add_column("Provider")
    table.add_column("Instance")
    table.add_column("Total")
    table.add_column("New", justify="right")
    table.add_column("Re-observed", justify="right")
    table.add_column("Status")
    for r in results:
        status = "[green]ok[/]" if r.ok else f"[red]error[/] {r.error}"
        table.add_row(
            r.provider,
            r.instance,
            str(r.total),
            str(r.new),
            str(r.reobserved),
            status,
        )
    _console.print(table)
    if any(not r.ok for r in results):
        raise typer.Exit(code=1)


@intel_app.command(name="list")
def intel_list(
    type_: str | None = typer.Option(
        None,
        "--type",
        "-t",
        help="Filter by IOC type (ipv4, sha256, domain, ...).",
    ),
    limit: int = typer.Option(50, "--limit", "-n", min=1, max=10_000),
    search: str = typer.Option("", "--search", "-s", help="Substring filter."),
) -> None:
    """List IOCs from the local store."""
    store = store_mod.get_default_store()
    try:
        if search.strip():
            iocs = store.search(search, limit=limit)
        else:
            iocs = store.find(type_=type_, limit=limit)
        if not iocs:
            _console.print("[yellow](no IOCs)[/]")
            return
        table = Table(title=f"IOCs ({len(iocs)} of {store.count(type_=type_)})")
        table.add_column("ID", justify="right")
        table.add_column("Type")
        table.add_column("Value")
        table.add_column("Last Seen")
        for ioc in iocs:
            table.add_row(
                str(ioc.id),
                ioc.type,
                ioc.value[:80],
                ioc.last_seen.strftime("%Y-%m-%d %H:%M"),
            )
        _console.print(table)
    finally:
        store.database.close()


@intel_app.command(name="export")
def intel_export(
    format_: str = typer.Option(
        "stix",
        "--format",
        "-f",
        help="Export format. Currently only 'stix' (STIX 2.1 JSON bundle).",
    ),
    type_: str | None = typer.Option(
        None,
        "--type",
        "-t",
        help="Filter by IOC type (ipv4, sha256, cve, ...).",
    ),
    limit: int = typer.Option(1000, "--limit", "-n", min=1, max=10_000),
    out: str | None = typer.Option(None, "--out", "-o", help="Write to FILE instead of stdout."),
) -> None:
    """Export IOCs from the local store as a STIX 2.1 bundle (or other format)."""
    if format_.lower() != "stix":
        _console.print(f"[red]Unknown format {format_!r}. Supported: stix[/]")
        raise typer.Exit(code=1)

    from secops_term.intel.stix_export import export_bundle_json

    store = store_mod.get_default_store()
    try:
        iocs = store.find(type_=type_, limit=limit)
    finally:
        store.database.close()

    bundle_json = export_bundle_json(iocs)
    if out:
        import pathlib

        p = pathlib.Path(out)
        p.write_text(bundle_json, encoding="utf-8")
        _console.print(f"[green]Wrote {len(iocs)} IOC(s) to {p}[/]")
    else:
        _console.print(bundle_json, markup=False, highlight=False)


def _run_wizard() -> None:
    """Top-level interactive wizard (Phase 0 scaffolding)."""
    paths.ensure_root_initialized()
    _console.print(
        "[bold]SecOps Terminal — Configuration Wizard[/]\n"
        "Phase 0 scaffolding. Pick a sub-command to configure a specific provider.\n"
    )
    _console.print("Available sub-commands:")
    _console.print("  secops-term config chronicle")
    _console.print("  secops-term config vision-one")
    _console.print("  secops-term config intel <provider> [--instance NAME]")
    _console.print("  secops-term config show")
    _console.print("  secops-term config test-all")
    _console.print("\nRun any of those, or `secops-term doctor` to verify your install.")


# AI subcommands


def _build_ai_bridge_candidates() -> list[TransportCandidate]:
    """Compose the default A → C transport list.

    Phase 4.1 ships A (headless) and C (clipboard); B (MCP) lands in 4.3.
    Headless first because it round-trips without user interaction;
    clipboard last because it requires the operator to paste manually.
    """
    candidates: list[TransportCandidate] = []
    try:
        path = resolve_claude_path()
        candidates.append(
            TransportCandidate(
                HeadlessClaudeBridge(claude_path=path),
                "claude-headless",
            )
        )
    except ClaudeNotFound:
        pass

    async def _stdin_response(instruction: str) -> str:
        # CLI-side response provider: print instructions, read until EOF
        # marker. Operator copies prompt to Claude.ai, pastes response,
        # types `:end` on its own line. ``input()`` is technically
        # blocking but we're inside an asyncio.run() that owns the event
        # loop — there's no concurrent work to starve, and Textual /
        # MCP paths use their own response_providers anyway.
        _console.print(f"[bold]{instruction}[/]")
        _console.print("Paste response below. Type ':end' on a line to finish.")
        lines: list[str] = []
        while True:
            line = await asyncio.to_thread(input)
            if line.strip() == ":end":
                break
            lines.append(line)
        return "\n".join(lines)

    candidates.append(
        TransportCandidate(
            ClipboardBridge(response_provider=_stdin_response),
            "clipboard",
        )
    )
    return candidates


@ai_app.command(name="status")
def ai_status() -> None:
    """Show which AI transports are healthy."""
    table = Table(title="AI bridge transports")
    table.add_column("Transport")
    table.add_column("Healthy")
    table.add_column("Detail")

    async def _probe() -> list[tuple[str, bool, str]]:
        rows: list[tuple[str, bool, str]] = []
        for c in _build_ai_bridge_candidates():
            try:
                ok = await c.bridge.health_check()
                rows.append((c.name, ok, "ok" if ok else "unhealthy"))
            except Exception as exc:
                rows.append((c.name, False, f"{type(exc).__name__}: {exc}"))
        return rows

    rows = asyncio.run(_probe())
    for name, ok, detail in rows:
        table.add_row(name, "[green]yes[/]" if ok else "[red]no[/]", detail)
    _console.print(table)


@ai_app.command(name="query")
def ai_query(
    target: str = typer.Option(
        "udm",
        "--target",
        "-t",
        help="Target query language: udm (Chronicle) or tmv1 (Vision One).",
    ),
    question: str = typer.Argument(..., help="Natural-language question to translate."),
    debug_ai: bool = typer.Option(
        False,
        "--debug-ai",
        help="Include full prompt and response in audit log (sensitive!).",
    ),
) -> None:
    """Translate a natural-language question to a UDM or TMV1 query.

    The generated query is shown for review and **never auto-executed**
    — copy it into the Chronicle / Vision One UI manually.
    """
    if target not in ("udm", "tmv1"):
        _console.print(f"[red]--target must be 'udm' or 'tmv1', got {target!r}[/]")
        raise typer.Exit(code=2)
    # Narrow `target: str` to the Literal the rest of the AI module expects.
    qt: QueryTarget = target  # type: ignore[assignment]

    paths.ensure_root_initialized()
    audit_logger = audit.AuditLogger()

    async def _run() -> None:
        try:
            bridge = await compose_bridge(
                _build_ai_bridge_candidates(),
                audit_logger=audit_logger,
                debug_ai=debug_ai,
            )
        except NoTransportAvailable as exc:
            _console.print(f"[red]No AI transport available:[/] {exc}")
            _console.print(
                "Install Claude Code (https://claude.ai/code) or ensure "
                "pyperclip can talk to your system clipboard."
            )
            raise typer.Exit(code=1) from exc
        _console.print(f"[dim]Using transport: [bold]{bridge.transport}[/][/]")
        try:
            result = await generate_query(
                bridge,
                target=qt,
                question=question,
            )
        except AIBridgeError as exc:
            _console.print(f"[red]AI bridge failed:[/] {exc}")
            raise typer.Exit(code=1) from exc
        _console.print()
        _console.print("[bold]Generated query:[/]")
        _console.print(result.query)
        _console.print()
        if result.validation.errors:
            _console.print("[red]Validation errors:[/]")
            for e in result.validation.errors:
                _console.print(f"  - {e}")
        if result.validation.warnings:
            _console.print("[yellow]Validation warnings:[/]")
            for w in result.validation.warnings:
                _console.print(f"  - {w}")
        if result.validation.ok and not result.validation.warnings:
            _console.print("[green]Validation: ok[/]")
        _console.print(
            "\n[bold yellow]Review before running.[/] "
            "This CLI never auto-executes generated queries."
        )

    asyncio.run(_run())


@app.command(name="mcp-serve")
def mcp_serve(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Bind address - MUST be loopback (127.0.0.1 / ::1).",
    ),
    port: int = typer.Option(8765, "--port", "-p", min=1024, max=65535, help="TCP port."),
    auth_required: bool = typer.Option(
        False,
        "--auth-required",
        help="Require Authorization: Bearer <token> on every call. "
        "Token is read from the keyring service `secops-term:mcp:default`.",
    ),
    rate: int = typer.Option(
        60,
        "--rate",
        min=1,
        max=10000,
        help="Per-tool rate limit (calls per minute).",
    ),
) -> None:
    """Run the MCP server (Transport B) so Claude clients can call our tools.

    Loopback-bind only. Optional bearer-token auth from keyring. Each tool
    call is rate-limited and audited (kind=mcp_tool_call).
    """
    from secops_term.mcp.server import MCPServerError, build_fastmcp_server

    paths.ensure_root_initialized()
    audit_logger = audit.AuditLogger()

    expected_token: str | None = None
    if auth_required:
        mgr = secrets.get_manager()
        expected_token = mgr.get_secret("mcp", "default", "bearer_token")
        if not expected_token:
            _console.print(
                "[red]--auth-required set but no bearer token in keyring "
                "(secops-term:mcp:default/bearer_token).[/]\n"
                "Set one via the wizard or `mgr.set_secret('mcp', 'default', "
                "'bearer_token', '<token>')`."
            )
            raise typer.Exit(code=1)

    try:
        server = build_fastmcp_server(
            host=host,
            port=port,
            audit_logger=audit_logger,
            expected_token=expected_token,
            per_tool_rate=rate,
        )
    except MCPServerError as exc:
        _console.print(f"[red]MCP server config error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    _console.print(
        f"[green]MCP server listening on http://{host}:{port}[/]"
        f" (auth={'required' if expected_token else 'disabled'},"
        f" rate={rate}/min)"
    )
    _console.print("[dim]Ctrl-C to stop.[/]")
    try:
        server.run("streamable-http")
    except KeyboardInterrupt:
        _console.print("\n[yellow]MCP server stopped.[/]")


# Playbook subcommands


@playbooks_app.command(name="list")
def playbooks_list() -> None:
    """List YAML playbooks in ~/.secops-term/playbooks/."""
    from secops_term.playbooks import loader as pb_loader

    paths.ensure_root_initialized()
    files = pb_loader.list_playbooks()
    if not files:
        _console.print(
            f"[yellow]No playbooks in {pb_loader.playbooks_root()}[/]\n"
            "Run `secops-term playbooks init` to install the bundled examples."
        )
        return
    table = Table(title=f"Playbooks ({len(files)})")
    table.add_column("Name")
    table.add_column("Trigger")
    table.add_column("Steps")
    table.add_column("Description")
    for path in files:
        name = path.stem
        try:
            pb = pb_loader.load_playbook_file(path)
        except Exception as exc:  # malformed file — show but flag
            table.add_row(name, "[red]ERROR[/]", "-", f"{type(exc).__name__}: {exc}")
            continue
        desc = (pb.description or "").strip().replace("\n", " ")
        table.add_row(name, pb.trigger.type, str(len(pb.steps)), desc[:60])
    _console.print(table)


@playbooks_app.command(name="show")
def playbooks_show(name: str = typer.Argument(...)) -> None:
    """Print the parsed playbook (post-validation)."""
    from secops_term.playbooks import loader as pb_loader

    paths.ensure_root_initialized()
    try:
        pb = pb_loader.load_playbook_by_name(name)
    except pb_loader.PlaybookError as exc:
        _console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    _console.print(f"[bold]{pb.name}[/]")
    if pb.description:
        _console.print(pb.description)
    _console.print(f"\n[cyan]trigger[/]: {pb.trigger}")
    _console.print(f"[cyan]timeout_seconds[/]: {pb.timeout_seconds}")
    _console.print(f"\n[cyan]steps[/] ({len(pb.steps)}):")
    for step in pb.steps:
        _console.print(f"  [bold]{step.id}[/] ({step.type})")
        if step.when:
            _console.print(f"    when: {step.when}")


@playbooks_app.command(name="init")
def playbooks_init(force: bool = typer.Option(False, "--force")) -> None:
    """Copy the three bundled example playbooks into the user playbooks directory."""
    from importlib import resources

    from secops_term.playbooks import loader as pb_loader

    paths.ensure_root_initialized()
    target = pb_loader.playbooks_root()
    target.mkdir(parents=True, exist_ok=True)
    pkg = "secops_term.playbooks.examples"
    written: list[str] = []
    skipped: list[str] = []
    for filename in (
        "high-conf-ioc-followup.yaml",
        "daily-feed-pull.yaml",
        "weekly-osint-roundup.yaml",
    ):
        dest = target / filename
        if dest.exists() and not force:
            skipped.append(filename)
            continue
        src_text = resources.files(pkg).joinpath(filename).read_text(encoding="utf-8")
        dest.write_text(src_text, encoding="utf-8")
        written.append(filename)
    if written:
        _console.print(f"[green]Wrote {len(written)} playbook(s)[/] to {target}:")
        for f in written:
            _console.print(f"  - {f}")
    if skipped:
        _console.print(
            f"[yellow]Skipped {len(skipped)} (already exist; pass --force to overwrite):[/]"
        )
        for f in skipped:
            _console.print(f"  - {f}")


@playbooks_app.command(name="run")
def playbooks_run(
    name: str = typer.Argument(...),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Walk the playbook without making any network calls."
    ),
    ioc_id: int | None = typer.Option(
        None, "--ioc-id", help="Bind retro_hunt steps to this IOC (required for ioc_added trigger)."
    ),
) -> None:
    """Execute a playbook end-to-end (with --dry-run for a no-side-effects walk)."""
    from secops_term.playbooks import (
        build_default_runners,
        build_runners_with_ioc,
    )
    from secops_term.playbooks import engine as engine_mod
    from secops_term.playbooks import loader as pb_loader

    paths.ensure_root_initialized()
    try:
        pb = pb_loader.load_playbook_by_name(name)
    except pb_loader.PlaybookError as exc:
        _console.print(f"[red]Could not load {name!r}:[/] {exc}")
        raise typer.Exit(code=1) from exc

    runners = build_runners_with_ioc(ioc_id) if ioc_id is not None else build_default_runners()
    audit_logger = audit.AuditLogger()
    engine = engine_mod.Engine(
        runners=runners,
        audit_logger=audit_logger,
        dry_run=dry_run,
    )

    # If the trigger is `ioc_added`, the operator must pass --ioc-id; the
    # engine accepts an `ioc` dict here so retro_hunt / template
    # interpolation has something to work with.
    ioc_ctx: dict[str, Any] | None = None
    if ioc_id is not None:
        from secops_term.intel import store as store_mod

        ioc = store_mod.get_default_store().get_by_id(ioc_id)
        if ioc is None:
            _console.print(f"[red]No IOC with id={ioc_id}[/]")
            raise typer.Exit(code=1)
        ioc_ctx = {
            "id": ioc.id,
            "type": ioc.type,
            "value": ioc.value,
            "confidence": ioc.confidence or 0,
            "tags": list(ioc.tags),
        }
    elif pb.trigger.type == "ioc_added":
        _console.print("[red]This playbook has trigger `ioc_added` — pass --ioc-id <N>.[/]")
        raise typer.Exit(code=2)

    run_result = asyncio.run(engine.run(pb, ioc=ioc_ctx))

    table = Table(
        title=(
            f"{pb.name} {'(dry-run)' if dry_run else ''} - "
            f"{'OK' if run_result.overall_ok else 'FAIL'}"
        )
    )
    table.add_column("Step")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Detail")
    for s in run_result.steps:
        if s.skipped:
            status = "[yellow]skipped[/]"
            detail = "when: false"
        elif s.ok:
            status = "[green]ok[/]"
            detail = f"{s.attempts} attempt(s) · {s.latency_ms:.1f}ms"
        else:
            status = "[red]failed[/]"
            detail = (s.error or "")[:80]
        table.add_row(s.step_id, s.type, status, detail)
    _console.print(table)
    if not run_result.overall_ok:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
