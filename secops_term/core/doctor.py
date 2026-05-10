"""``secops-term doctor`` checks.

Per brief v3 §3.5.1 + Phase 0 §10. Runs every check in sequence and returns
a list of :class:`CheckResult` so the CLI can render a Rich table.

Checks (Phase 0):

- root directory exists with restrictive ACL
- config.toml file: present + restrictive ACL (or absent)
- audit.jsonl: present + restrictive ACL + chain verifies (or absent)
- secrets.enc: present + restrictive ACL (or absent)
- keyring backend: usable, or fallback configured
- ``claude`` binary: on PATH (advisory; AI features are Phase 4)
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from secops_term.core import audit, config_io, paths


@dataclass(frozen=True)
class CheckResult:
    """Single doctor-check outcome."""

    name: str
    ok: bool
    detail: str


def run_doctor() -> list[CheckResult]:
    """Execute every Phase 0 + 2 + 3 + 4 + 5 check, in order."""
    return [
        _check_root_dir(),
        _check_config_file(),
        _check_secrets_file(),
        _check_audit_log(),
        _check_keyring(),
        _check_claude_binary(),
        _check_chronicle(),
        _check_vision_one(),
        _check_deep_security(),
        _check_ai_bridge(),
        _check_notifications(),
        _check_playbooks(),
    ]


def _check_root_dir() -> CheckResult:
    root = paths.get_root()
    if not root.exists():
        # Fresh install — not a failure. ACL checks fire only when the
        # directory exists and might be misconfigured.
        return CheckResult(
            "root directory",
            ok=True,
            detail=f"{root} not yet created (run `secops-term config` to set up)",
        )
    try:
        paths.verify_restrictive_acl(root, is_dir=True)
    except paths.RestrictiveACLError as exc:
        return CheckResult("root directory", ok=False, detail=str(exc))
    return CheckResult("root directory", ok=True, detail=str(root))


def _check_config_file() -> CheckResult:
    path = config_io.config_path()
    if not path.exists():
        return CheckResult(
            "config.toml", ok=True, detail="not yet created (no providers configured)"
        )
    try:
        paths.verify_restrictive_acl(path)
    except paths.RestrictiveACLError as exc:
        return CheckResult("config.toml", ok=False, detail=str(exc))
    try:
        data = config_io.load_config()
    except config_io.ConfigError as exc:
        return CheckResult("config.toml", ok=False, detail=str(exc))
    return CheckResult(
        "config.toml",
        ok=True,
        detail=f"{path.name}: {len(data)} top-level table(s)",
    )


def _check_secrets_file() -> CheckResult:
    root = paths.get_root()
    if not root.exists():
        return CheckResult("secrets.enc", ok=True, detail="root not yet created")
    path = root / "secrets.enc"
    if not path.exists():
        return CheckResult(
            "secrets.enc",
            ok=True,
            detail="not present (keyring backend or no secrets stored)",
        )
    try:
        paths.verify_restrictive_acl(path)
    except paths.RestrictiveACLError as exc:
        return CheckResult("secrets.enc", ok=False, detail=str(exc))
    return CheckResult("secrets.enc", ok=True, detail=f"{path.name} present")


def _check_audit_log() -> CheckResult:
    root = paths.get_root()
    if not root.exists():
        return CheckResult("audit chain", ok=True, detail="root not yet created")
    active = root / "audit.jsonl"
    rotated = list(root.glob("audit-*.jsonl"))
    if not active.exists() and not rotated:
        return CheckResult("audit chain", ok=True, detail="no audit log yet")
    for p in [*rotated, active]:
        if p.exists():
            try:
                paths.verify_restrictive_acl(p)
            except paths.RestrictiveACLError as exc:
                return CheckResult("audit chain", ok=False, detail=f"{p.name}: {exc}")
    try:
        files, entries = audit.verify_chain()
    except audit.ChainBroken as exc:
        return CheckResult("audit chain", ok=False, detail=str(exc))
    return CheckResult(
        "audit chain",
        ok=True,
        detail=f"verified {entries} entries across {files} file(s)",
    )


def _check_keyring() -> CheckResult:
    """Detect whether the OS keyring is usable.

    A keyring failure is NOT a doctor failure: the encrypted-file fallback
    is the supported alternative. The check reports which backend is in
    play so the user understands their secrets path.
    """
    try:
        import keyring as _kr
    except ImportError:
        return CheckResult(
            "keyring", ok=True, detail="not installed; encrypted-file fallback in effect"
        )
    try:
        backend = _kr.get_keyring()
    except Exception as exc:
        return CheckResult(
            "keyring",
            ok=True,
            detail=f"unavailable: {exc!s}; encrypted-file fallback in effect",
        )
    name = f"{type(backend).__module__}.{type(backend).__name__}"
    if "fail" in name.lower() or "null" in name.lower():
        return CheckResult(
            "keyring",
            ok=True,
            detail=f"{name}; encrypted-file fallback in effect",
        )
    return CheckResult("keyring", ok=True, detail=name)


def _check_claude_binary() -> CheckResult:
    """Advisory: ``claude`` on PATH so the AI bridge has Transport A available.

    Phase 0 doesn't ship the bridge logic, but doctor reports the state so
    the user knows whether Phase 4 will work out of the box.
    """
    path = shutil.which("claude")
    if path is None:
        return CheckResult(
            "claude on PATH",
            ok=True,
            detail="not found (AI bridge will fall back to clipboard in Phase 4)",
        )
    return CheckResult("claude on PATH", ok=True, detail=path)


def _check_chronicle() -> CheckResult:
    """Lightweight Chronicle config sanity-check.

    Phase 2.3 only verifies "is the [chronicle] block present and the
    keyring entry set up?"; the live API probe lives in
    ``config test chronicle`` / ``config test-all``. Doing the network
    call here would slow ``doctor`` down for everyone whose Chronicle is
    correctly configured.
    """
    from secops_term.chronicle import factory as chronicle_factory
    from secops_term.chronicle.client import ChronicleError

    try:
        cfg = config_io.load_config()
    except config_io.ConfigError:
        # Surfaced separately by the config.toml check.
        return CheckResult("chronicle", ok=True, detail="see config.toml check")
    if "chronicle" not in cfg:
        return CheckResult("chronicle", ok=True, detail="not configured")
    try:
        client = chronicle_factory.build_chronicle_client(cfg_data=cfg)
    except ChronicleError as exc:
        return CheckResult("chronicle", ok=False, detail=str(exc))
    if client is None:
        return CheckResult("chronicle", ok=True, detail="not configured")
    return CheckResult(
        "chronicle",
        ok=True,
        detail=(
            f"configured ({client.cfg.region}/{client.cfg.customer_id}) - "
            f"run `config test chronicle` for a live probe"
        ),
    )


def _check_vision_one() -> CheckResult:
    """Vision One config-only sanity check (no live probe)."""
    from secops_term.trendmicro import factory as tm_factory
    from secops_term.trendmicro.vision_one import VisionOneError

    try:
        cfg = config_io.load_config()
    except config_io.ConfigError:
        return CheckResult("vision_one", ok=True, detail="see config.toml check")
    if "vision_one" not in cfg:
        return CheckResult("vision_one", ok=True, detail="not configured")
    try:
        client = tm_factory.build_vision_one_client(cfg_data=cfg)
    except VisionOneError as exc:
        return CheckResult("vision_one", ok=False, detail=str(exc))
    if client is None:
        return CheckResult("vision_one", ok=True, detail="not configured")
    return CheckResult(
        "vision_one",
        ok=True,
        detail="configured - run `config test vision_one` for a live probe",
    )


def _check_deep_security() -> CheckResult:
    """Deep Security config-only sanity check (no live probe)."""
    from secops_term.trendmicro import factory as tm_factory
    from secops_term.trendmicro.deep_security import DeepSecurityError

    try:
        cfg = config_io.load_config()
    except config_io.ConfigError:
        return CheckResult("deep_security", ok=True, detail="see config.toml check")
    if "deep_security" not in cfg:
        return CheckResult("deep_security", ok=True, detail="not configured")
    try:
        client = tm_factory.build_deep_security_client(cfg_data=cfg)
    except DeepSecurityError as exc:
        return CheckResult("deep_security", ok=False, detail=str(exc))
    if client is None:
        return CheckResult("deep_security", ok=True, detail="not configured")
    return CheckResult(
        "deep_security",
        ok=True,
        detail=(
            f"configured ({client.cfg.deployment_type}) - "
            "run `config test deep_security` for a live probe"
        ),
    )


def _check_ai_bridge() -> CheckResult:
    """Report which AI bridge transports are likely usable.

    Same offline-friendly philosophy as the Chronicle / V1 / DS checks:
    no live network calls, no subprocess invocation. We just look at
    whether ``claude`` is on PATH (Transport A) and whether
    ``pyperclip`` imports (Transport C). MCP server (Transport B) is a
    server we host, not a transport we probe — listed separately when
    enabled in config.
    """
    transports: list[str] = []
    if shutil.which("claude") is not None:
        transports.append("headless")
    try:
        import pyperclip  # type: ignore[import-not-found,import-untyped,unused-ignore]

        _ = pyperclip
        transports.append("clipboard")
    except ImportError:
        pass
    if not transports:
        return CheckResult(
            "ai bridge",
            ok=False,
            detail=("no transports available - install Claude Code or pyperclip"),
        )
    return CheckResult(
        "ai bridge",
        ok=True,
        detail=f"available: {', '.join(transports)}",
    )


def _check_notifications() -> CheckResult:
    """Walk ``[notifications.<notifier>.<instance>]`` blocks; report counts.

    Same offline-friendly philosophy as the other checks: we list what's
    configured and verify it can be constructed (which checks the
    keyring entry exists where required), but the *live* HTTP probe is
    behind ``config test-all``.
    """
    try:
        from secops_term.notifications import orchestrator as notify_orch
    except ImportError:  # pragma: no cover - notifications package always present
        return CheckResult("notifications", ok=True, detail="package not loaded")
    try:
        targets = notify_orch.list_configured()
    except config_io.ConfigError:
        return CheckResult("notifications", ok=True, detail="see config.toml check")
    if not targets:
        return CheckResult("notifications", ok=True, detail="not configured")
    channels = sorted({t.channel for t in targets})
    return CheckResult(
        "notifications",
        ok=True,
        detail=(
            f"{len(targets)} channel(s): {', '.join(channels[:6])}"
            + ("..." if len(channels) > 6 else "")
        ),
    )


def _check_playbooks() -> CheckResult:
    """Count loadable / unloadable YAML files in the playbooks directory."""
    try:
        from secops_term.playbooks import loader as pb_loader
    except ImportError:  # pragma: no cover - package always present
        return CheckResult("playbooks", ok=True, detail="package not loaded")
    paths_list = pb_loader.list_playbooks()
    if not paths_list:
        return CheckResult("playbooks", ok=True, detail="not configured")
    bad: list[str] = []
    for p in paths_list:
        try:
            pb_loader.load_playbook_file(p)
        except pb_loader.PlaybookError as exc:
            bad.append(f"{p.stem}: {type(exc).__name__}")
    if bad:
        return CheckResult(
            "playbooks",
            ok=False,
            detail=f"{len(paths_list)} found, {len(bad)} invalid: {bad[0]}",
        )
    return CheckResult(
        "playbooks",
        ok=True,
        detail=f"{len(paths_list)} valid playbook(s)",
    )


def overall_ok(results: list[CheckResult]) -> bool:
    """Return True iff every check passed."""
    return all(r.ok for r in results)


def format_table(results: list[CheckResult]) -> list[tuple[str, str, str]]:
    """Format check results as a list of (check, status, detail) rows."""
    return [(r.name, "OK" if r.ok else "FAIL", r.detail) for r in results]


__all__ = ["CheckResult", "format_table", "overall_ok", "run_doctor"]


# Re-export for convenience.
Path = Path
