"""PyInstaller spec for SecOps Terminal v0.6.0.

Build a single-file executable for the current platform:

    pip install "secops-term[build]"
    pyinstaller secops_term.spec

Output lands in ``dist/secops-term`` (directory mode, not onefile) so that
platform-specific keyring backends and C extensions can be bundled alongside
the binary without hidden-import wrestling.

Cross-platform notes
--------------------
Windows
    keyring uses the Windows Credential Manager backend (``keyring.backends.Windows``).
    The ``pywin32`` wheel is platform-specific; PyInstaller will collect it
    automatically on a Windows build host.

macOS
    keyring uses the macOS Keychain backend (``keyring.backends.macOS``).
    Code-sign with ``codesign --deep --force --sign - dist/secops-term/secops-term``
    before distribution.

Linux
    keyring may use the SecretService (GNOME Keyring / KWallet) backend.
    Operators without a D-Bus session daemon fall back to the Argon2id-Fernet
    encrypted-file backend automatically (see ``secops_term/core/secrets.py``).
    Distribute the directory bundle; AppImage packaging is straightforward.
"""

from pathlib import Path

_HERE = Path(SPECPATH)  # noqa: F821  — injected by PyInstaller

# ---------------------------------------------------------------------------
# Discover playbook example YAMLs to bundle as data files.
# ---------------------------------------------------------------------------
_EXAMPLES_DIR = _HERE / "secops_term" / "playbooks" / "examples"
_YAML_DATAS = [
    (str(p), "secops_term/playbooks/examples")
    for p in _EXAMPLES_DIR.glob("*.yaml")
]

# ---------------------------------------------------------------------------
# Hidden imports — modules loaded dynamically via the plugin registry.
# PyInstaller can't detect these through static analysis; list them all.
# ---------------------------------------------------------------------------
_HIDDEN_IMPORTS = [
    # Intel providers (discovered at runtime via discover_modules()).
    "secops_term.intel.providers.otx",
    "secops_term.intel.providers.abuse_ch",
    "secops_term.intel.providers.rss",
    "secops_term.intel.providers.virustotal",
    "secops_term.intel.providers.greynoise",
    "secops_term.intel.providers.abuseipdb",
    "secops_term.intel.providers.nvd",
    # Notifiers (same discovery mechanism).
    "secops_term.notifications.generic_json",
    "secops_term.notifications.slack",
    "secops_term.notifications.teams",
    # Keyring backends — platform-specific; PyInstaller may miss them.
    "keyring.backends",
    "keyring.backends.fail",
    "keyring.backends.null",
    # Windows Credential Manager (no-op on non-Windows builds).
    "keyring.backends.Windows",
    # macOS Keychain (no-op on non-macOS builds).
    "keyring.backends.macOS",
    # SecretService / D-Bus (Linux).
    "keyring.backends.SecretService",
    "keyring.backends.kwallet",
    # Google auth (Chronicle service-account OAuth2).
    "google.auth",
    "google.auth.transport.requests",
    "google.oauth2.service_account",
    # ruamel.yaml safe loader.
    "ruamel.yaml",
    "ruamel.yaml.main",
    # argon2 KDF (Fernet fallback keyring backend).
    "argon2",
    "argon2.low_level",
    # feedparser (RSS provider).
    "feedparser",
    # iocextract and its transitive dep on requests.
    "iocextract",
    "requests",
    "requests.adapters",
    "requests.auth",
    # selectolax (HTML scraper).
    "selectolax.parser",
    # MCP server (optional; include so the binary supports it without reinstall).
    "mcp",
    # pyperclip (clipboard AI transport).
    "pyperclip",
    # pypdf (optional PDF scraping — degrades gracefully if not installed).
    "pypdf",
]

# ---------------------------------------------------------------------------
# Collect data: Textual bundles CSS + widget templates inside the package.
# ---------------------------------------------------------------------------
from PyInstaller.utils.hooks import collect_all  # noqa: E402

_textual_datas, _textual_binaries, _textual_hiddenimports = collect_all("textual")

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
a = Analysis(  # noqa: F821 — injected by PyInstaller
    scripts=["secops_term/cli.py"],
    pathex=[str(_HERE)],
    binaries=_textual_binaries,
    datas=_YAML_DATAS + _textual_datas,
    hiddenimports=_HIDDEN_IMPORTS + _textual_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Development / test dependencies — never needed in the distributable.
        "pytest",
        "ruff",
        "mypy",
        "respx",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)  # noqa: F821

# ---------------------------------------------------------------------------
# Executable — directory mode (not onefile) for easier keyring DLL pickup.
# ---------------------------------------------------------------------------
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="secops-term",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="secops-term",
)
