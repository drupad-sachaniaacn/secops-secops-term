#!/usr/bin/env python
"""Seed script — populate config + IOC store with realistic demo data.

Run once from the repo root after installing the package:

    python scripts/seed_dev.py

What it does
------------
1. Writes ``~/.secops-term/config.toml`` with all seven intel providers and
   the three notifiers configured (non-secret, non-URL values only — secrets
   go to the OS keyring separately; see the "Keyring" section below).
2. Seeds the SQLite IOC store with ~60 realistic-looking IOCs across all 9 types
   so the Dashboard, Intel, and Retro Hunt screens look populated on first launch.
3. Seeds the ``retro_hunt_jobs`` table with jobs in every status so the
   Retro Hunts screen shows a realistic queue.
4. Writes DEMO marker keys into the OS keyring for every provider so the
   ``Config`` screen health-check button returns real-looking (but invalid)
   results instead of "secret not found".

Keyring entries written
-----------------------
These are clearly named "DEMO-*" so you can spot and delete them in
Windows Credential Manager (search "secops-term") after testing:

    secops-term:otx:default           api_token  = DEMO-otx-key-replace-me
    secops-term:virustotal:default    api_key    = DEMO-vt-key-replace-me
    secops-term:greynoise:default     api_key    = DEMO-gn-key-replace-me
    secops-term:abuseipdb:default     api_key    = DEMO-aipdb-key-replace-me
    secops-term:nvd:default           api_key    = DEMO-nvd-key-replace-me

To replace a demo key with a real one:

    secops-term config intel otx          # interactive wizard for OTX
    secops-term config intel virustotal   # etc.

Or directly via keyring:

    python -c "import keyring; keyring.set_password('secops-term:otx:default', 'api_token', 'YOUR_REAL_KEY')"

Cleanup
-------
To wipe the demo data and start fresh:

    Remove-Item -Recurse "$env:USERPROFILE\\.secops-term"   # Windows PowerShell
    rm -rf ~/.secops-term                                    # macOS / Linux

The keyring entries survive a data-root wipe — delete them in Windows
Credential Manager or via:

    python -c "import keyring; keyring.delete_password('secops-term:otx:default', 'api_token')"
"""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

# ── Venv auto-reinvocation ────────────────────────────────────────────────────
# If running under the system Python (missing keyring / pywin32 / etc.),
# automatically re-invoke with the project venv so the user can just type
# "python scripts/seed_dev.py" without activating the venv first.
_VENV_PYTHON = (
    _REPO_ROOT / ".venv" / "Scripts" / "python.exe"  # Windows
    if sys.platform == "win32"
    else _REPO_ROOT / ".venv" / "bin" / "python"  # macOS / Linux
)
if _VENV_PYTHON.exists() and Path(sys.executable).resolve() != _VENV_PYTHON.resolve():
    # Probe before re-invoking — the venv shell exists but the underlying
    # interpreter may have been removed (common with uv-managed Pythons).
    _probe = subprocess.run(  # noqa: S603
        [str(_VENV_PYTHON), "-c", "import sys; print(sys.version)"],
        capture_output=True,
        timeout=10,
    )
    if _probe.returncode != 0:
        _err = _probe.stderr.decode(errors="replace").strip().splitlines()[0]
        print(
            f"[seed] WARNING: venv Python is broken ({_err}).\n"
            f"[seed] Rebuild the venv with:\n"
            f"[seed]   python -m venv .venv --clear\n"
            f"[seed]   .venv\\Scripts\\pip install -e \".[dev]\"\n"
            f"[seed] Then re-run this script.",
            flush=True,
        )
        sys.exit(1)
    print(f"[seed] Re-invoking with venv Python: {_VENV_PYTHON}", flush=True)
    result = subprocess.run([str(_VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]])  # noqa: S603
    sys.exit(result.returncode)

# Ensure repo root is on sys.path for editable installs.
sys.path.insert(0, str(_REPO_ROOT))


def main() -> None:
    _setup_config()
    _seed_keyring()
    _seed_ioc_store()
    print("\n[OK]  Demo seed complete.  Launch the TUI with:  secops-term tui")
    print("   or run health checks:                       secops-term doctor")


# ──────────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────────


def _setup_config() -> None:
    print("[1/3] Writing ~/.secops-term/config.toml ...")
    from secops_term.core import config_io, paths

    paths.ensure_root_initialized()

    config: dict = {
        "intel_providers": {
            "otx": {
                "default": {
                    "enabled": True,
                    "pulse_limit": 20,
                    "types": ["ipv4", "domain", "url", "sha256", "md5", "cve"],
                }
            },
            "abuse_ch": {
                "default": {
                    "enabled": True,
                    "feeds": ["threatfox", "urlhaus", "malwarebazaar", "feodotracker"],
                    "limit": 100,
                }
            },
            "rss": {
                "bleeping_computer": {
                    "enabled": True,
                    "url": "https://www.bleepingcomputer.com/feed/",
                    "scrape_articles": True,
                },
                "krebs": {
                    "enabled": True,
                    "url": "https://krebsonsecurity.com/feed/",
                    "scrape_articles": True,
                },
                "sans_isc": {
                    "enabled": True,
                    "url": "https://isc.sans.edu/rssfeed_full.xml",
                    "scrape_articles": False,
                },
            },
            "virustotal": {
                "default": {
                    "enabled": True,
                    "owner": "your-vt-username",
                    "query": "type:malware p:5+",
                    "limit": 40,
                }
            },
            "greynoise": {
                "default": {
                    "enabled": True,
                    "query": "classification:malicious",
                    "limit": 100,
                }
            },
            "abuseipdb": {
                "default": {
                    "enabled": True,
                    "confidence_minimum": 75,
                    "limit": 500,
                }
            },
            "nvd": {
                "default": {
                    "enabled": True,
                    "min_cvss_v3": 7.0,
                    "limit": 200,
                }
            },
        },
        "chronicle": {
            "project_id": "your-gcp-project-id",
            "customer_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "region": "us",
        },
        "vision_one": {
            "api_url": "https://api.xdr.trendmicro.com",
            "region": "us",
        },
        "deep_security": {
            "api_url": "https://your-dsm.example.com:4119",
        },
        "notifiers": {
            "slack": {
                "default": {
                    "enabled": True,
                    "channel": "#secops-alerts",
                }
            },
            "teams": {
                "soc_channel": {
                    "enabled": True,
                }
            },
            "generic_json": {
                "siem_ingest": {
                    "enabled": True,
                    "url": "https://your-siem.example.com/api/ingest",
                    "method": "POST",
                }
            },
        },
        "hunt": {
            "platforms": ["chronicle", "vision_one"],
            "max_concurrent": 4,
        },
        "ai": {
            "transport": "clipboard",
        },
    }

    config_io.save_config(config)
    print(f"   Written to {config_io.config_path()}")


# ──────────────────────────────────────────────────────────────────────────────
# Keyring
# ──────────────────────────────────────────────────────────────────────────────


_DEMO_KEYS: list[tuple[str, str, str]] = [
    # (service, username/field, demo_value)
    ("secops-term:otx:default", "api_token", "DEMO-otx-key-replace-me"),
    ("secops-term:virustotal:default", "api_key", "DEMO-vt-key-replace-me"),
    ("secops-term:greynoise:default", "api_key", "DEMO-gn-key-replace-me"),
    ("secops-term:abuseipdb:default", "api_key", "DEMO-aipdb-key-replace-me"),
    ("secops-term:nvd:default", "api_key", "DEMO-nvd-key-replace-me"),
]


def _seed_keyring() -> None:
    print("[2/3] Writing DEMO keys to OS keyring ...")
    try:
        import keyring

        for service, field, value in _DEMO_KEYS:
            keyring.set_password(service, field, value)
            print(f"   {service}  [{field}]")
        print("   [!]  These are placeholder values -- replace with real keys for live pulls.")
    except Exception as exc:
        print(f"   [!]  Keyring unavailable ({exc}) — skipping. Run providers with real keys later.")


# ──────────────────────────────────────────────────────────────────────────────
# IOC store seed data
# ──────────────────────────────────────────────────────────────────────────────


def _seed_ioc_store() -> None:
    print("[3/3] Seeding IOC store and retro hunt queue ...")
    from secops_term.core import db as core_db
    from secops_term.intel import store as store_mod

    database = core_db.Database()
    database.apply_migrations(core_db.discover_migrations())
    s = store_mod.IOCStore(database)

    now = datetime.now(UTC)

    records = _make_records(now)
    for r in records:
        s.upsert(r)

    # Seed retro hunt jobs in every status.
    ioc = s.find(limit=1)
    if ioc:
        ioc_id = ioc[0].id
        s.enqueue_retro_hunt(ioc_id, "chronicle")  # stays queued → chronicle
        s.enqueue_retro_hunt(ioc_id, "vision_one")  # stays queued → vision_one

        # Claim one → running.
        s.next_pending_job("chronicle")

        # Completed job.
        done_ioc = s.find(type_="sha256", limit=1)
        if done_ioc:
            done_id = done_ioc[0].id
            s.enqueue_retro_hunt(done_id, "chronicle")
            j = s.next_pending_job("chronicle")
            if j:
                s.complete_job(j.id, hits=12, query='target.ip = "185.220.101.42"')

        # Failed job.
        err_ioc = s.find(type_="domain", limit=1)
        if err_ioc:
            err_id = err_ioc[0].id
            s.enqueue_retro_hunt(err_id, "vision_one")
            je = s.next_pending_job("vision_one")
            if je:
                s.fail_job(je.id, "API rate limit exceeded — retry after 60s")

    total = s.count()
    database.close()
    print(f"   Seeded {len(records)} IOCs (store total: {total})")
    print("   Retro hunt jobs: queued/running/done/error all represented")


def _make_records(now: datetime) -> list:  # list[IntelRecord]
    """Return ~60 realistic demo IntelRecords across all 9 IOC types."""
    from secops_term.intel.providers.base import IntelRecord

    def rec(
        *,
        source: str,
        type: str,
        value: str,
        age_hours: float = 0,
        confidence: int | None = None,
        context: str | None = None,
        tags: tuple[str, ...] = (),
        source_ref: str | None = None,
    ) -> IntelRecord:
        return IntelRecord(
            source=source,
            type=type,
            value=value,
            fetched_at=now - timedelta(hours=age_hours),
            confidence=confidence,
            context=context,
            source_ref=source_ref,
            tags=tags,
        )

    return [
        # ── IPv4 — known malicious / C2 IPs ───────────────────────────────
        rec(
            source="greynoise:default",
            type="ipv4",
            value="185.220.101.42",
            confidence=90,
            context="Tor exit node / scanner",
            tags=("tor", "scanner"),
            source_ref="https://viz.greynoise.io/ip/185.220.101.42",
        ),
        rec(
            source="greynoise:default",
            type="ipv4",
            value="194.165.16.29",
            confidence=85,
            context="malicious / cobalt-strike",
            tags=("cobalt-strike", "c2"),
        ),
        rec(
            source="abuseipdb:default",
            type="ipv4",
            value="45.142.212.100",
            confidence=97,
            context="AS50673 Serverius / Hosting",
            tags=("ssh-bruteforce",),
        ),
        rec(
            source="abuseipdb:default",
            type="ipv4",
            value="91.92.109.181",
            confidence=88,
            context="Frantech Solutions / VPN abuse",
            tags=("spam",),
        ),
        rec(
            source="abuseipdb:default",
            type="ipv4",
            value="179.60.150.34",
            confidence=75,
            context="LACNIC / brute force",
            age_hours=6,
        ),
        rec(
            source="abuse_ch:default",
            type="ipv4",
            value="162.247.74.200",
            tags=("feodotracker", "botnet-c2"),
            confidence=95,
            context="Feodo Tracker — Emotet C2",
        ),
        rec(
            source="abuse_ch:default",
            type="ipv4",
            value="109.201.133.100",
            tags=("feodotracker", "trickbot"),
            confidence=95,
        ),
        rec(
            source="otx:default",
            type="ipv4",
            value="5.188.206.14",
            context="AlienVault OTX pulse: RU botnet",
            age_hours=12,
        ),
        rec(
            source="otx:default",
            type="ipv4",
            value="37.49.230.75",
            context="AlienVault OTX pulse: QakBot C2",
            age_hours=2,
        ),
        # ── IPv6 ──────────────────────────────────────────────────────────
        rec(
            source="greynoise:default",
            type="ipv6",
            value="2001:db8:85a3::8a2e:370:7334",
            context="greynoise: malicious scanner",
            tags=("scanner",),
        ),
        rec(
            source="otx:default",
            type="ipv6",
            value="2606:4700:4700::1111",
            context="OTX: flagged in abuse report",
            age_hours=48,
        ),
        # ── Domain ────────────────────────────────────────────────────────
        rec(
            source="abuse_ch:default",
            type="domain",
            value="update-service.xyz",
            tags=("urlhaus", "malware-distribution"),
            confidence=90,
            context="URLhaus: malware download site",
        ),
        rec(
            source="abuse_ch:default",
            type="domain",
            value="cdn-secure-files.top",
            tags=("urlhaus",),
            confidence=85,
            context="URLhaus: phishing redirect",
        ),
        rec(
            source="otx:default",
            type="domain",
            value="microsoft-support-alert.com",
            context="OTX: tech-support-scam C2",
            age_hours=3,
        ),
        rec(
            source="otx:default",
            type="domain",
            value="accounts-google-verify.tk",
            context="OTX: credential-phishing landing page",
            age_hours=1,
        ),
        rec(
            source="rss:bleeping_computer",
            type="domain",
            value="lockbit3-decryptor.onion",
            context="BleepingComputer: LockBit 3.0 ransom site",
            age_hours=18,
        ),
        rec(
            source="rss:krebs",
            type="domain",
            value="invoice-secure-download.ru",
            context="KrebsOnSecurity: BEC phishing domain",
        ),
        rec(
            source="rss:sans_isc",
            type="domain",
            value="malicious-macro-host.pw",
            context="SANS ISC: macro malware staging",
        ),
        # ── URL ───────────────────────────────────────────────────────────
        rec(
            source="abuse_ch:default",
            type="url",
            value="https://cdn-secure-files.top/payload/agent.exe",
            tags=("urlhaus", "exe-download"),
            confidence=92,
            context="URLhaus: AgentTesla dropper",
        ),
        rec(
            source="abuse_ch:default",
            type="url",
            value="http://update-service.xyz/wp-content/uploads/gate.php",
            tags=("urlhaus", "gate"),
            confidence=88,
        ),
        rec(
            source="otx:default",
            type="url",
            value="https://accounts-google-verify.tk/login?redirect=gmail",
            context="OTX: Google credential phish",
            age_hours=2,
        ),
        rec(
            source="rss:bleeping_computer",
            type="url",
            value="https://invoice-secure-download.ru/INV-2024-6701.xlsm",
            context="BleepingComputer: Excel macro dropper",
            age_hours=5,
        ),
        # ── SHA256 ────────────────────────────────────────────────────────
        rec(
            source="virustotal:default",
            type="sha256",
            value="3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c",
            confidence=95,
            context="VT: AgentTesla stealer — 58/72 engines",
            tags=("agentTesla", "stealer"),
            source_ref="https://www.virustotal.com/gui/file/3b4c5d6e",
        ),
        rec(
            source="virustotal:default",
            type="sha256",
            value="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            confidence=88,
            context="VT: Cobalt Strike beacon — 44/72",
            tags=("cobalt-strike", "beacon"),
        ),
        rec(
            source="abuse_ch:default",
            type="sha256",
            value="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            tags=("malwarebazaar", "qakbot"),
            confidence=96,
            context="MalwareBazaar: QakBot loader",
            source_ref="https://bazaar.abuse.ch/sample/deadbeef",
        ),
        rec(
            source="abuse_ch:default",
            type="sha256",
            value="cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
            tags=("malwarebazaar", "emotet"),
            confidence=99,
            context="MalwareBazaar: Emotet epoch5 DLL",
        ),
        rec(
            source="otx:default",
            type="sha256",
            value="f0e1d2c3b4a5968778695a4b3c2d1e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c60",
            context="OTX: LockBit 3.0 ransomware binary",
            age_hours=8,
        ),
        rec(
            source="rss:krebs",
            type="sha256",
            value="1122334455667788990011223344556677889900112233445566778899001122",
            context="KrebsOnSecurity: phishing kit archive",
        ),
        # ── SHA1 ──────────────────────────────────────────────────────────
        rec(
            source="virustotal:default",
            type="sha1",
            value="aabbccddeeff00112233445566778899aabbccdd",
            confidence=82,
            context="VT: RedLine stealer component",
            tags=("redline", "stealer"),
        ),
        rec(
            source="abuse_ch:default",
            type="sha1",
            value="0011223344556677889900aabbccddeeff001122",
            tags=("malwarebazaar", "formbook"),
            confidence=91,
            context="MalwareBazaar: FormBook packer",
        ),
        rec(
            source="otx:default",
            type="sha1",
            value="1234567890abcdef1234567890abcdef12345678",
            context="OTX: Ursnif banking trojan",
            age_hours=24,
        ),
        # ── MD5 ───────────────────────────────────────────────────────────
        rec(
            source="virustotal:default",
            type="md5",
            value="d41d8cd98f00b204e9800998ecf8427e",
            confidence=78,
            context="VT: suspicious empty-file padding trick",
            tags=("evasion",),
        ),
        rec(
            source="abuse_ch:default",
            type="md5",
            value="098f6bcd4621d373cade4e832627b4f6",
            tags=("malwarebazaar", "remcos"),
            confidence=93,
            context="MalwareBazaar: Remcos RAT",
        ),
        rec(
            source="otx:default",
            type="md5",
            value="5d41402abc4b2a76b9719d911017c592",
            context="OTX: IcedID loader dropper",
            age_hours=16,
        ),
        rec(
            source="rss:sans_isc",
            type="md5",
            value="7215ee9c7d9dc229d2921a40e899ec5f",
            context="SANS ISC: PowerShell downloader stager",
        ),
        # ── Email ─────────────────────────────────────────────────────────
        rec(
            source="rss:krebs",
            type="email",
            value="invoice@invoice-secure-download.ru",
            context="KrebsOnSecurity: BEC sender address",
            age_hours=3,
        ),
        rec(
            source="otx:default",
            type="email",
            value="noreply@microsoft-support-alert.com",
            context="OTX: tech-support scam lure",
        ),
        rec(
            source="rss:bleeping_computer",
            type="email",
            value="accounts@accounts-google-verify.tk",
            context="BleepingComputer: phishing kit sender",
        ),
        rec(
            source="rss:sans_isc",
            type="email",
            value="hr-dept@malicious-macro-host.pw",
            context="SANS ISC: spear-phish lure pretending to be HR",
        ),
        # ── CVE ───────────────────────────────────────────────────────────
        rec(
            source="nvd:default",
            type="cve",
            value="CVE-2024-21413",
            confidence=None,
            context="Microsoft Outlook RCE — CVSS 9.8 critical. "
            "Hyperlink processing bypass allows credential theft via UNC path.",
            tags=("critical", "rce", "microsoft"),
            source_ref="https://nvd.nist.gov/vuln/detail/CVE-2024-21413",
        ),
        rec(
            source="nvd:default",
            type="cve",
            value="CVE-2024-3400",
            confidence=None,
            context="Palo Alto PAN-OS command injection — CVSS 10.0 critical. "
            "GlobalProtect feature exploited in the wild by UTA0218.",
            tags=("critical", "rce", "palo-alto", "itw"),
            source_ref="https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
        ),
        rec(
            source="nvd:default",
            type="cve",
            value="CVE-2024-1709",
            confidence=None,
            context="ConnectWise ScreenConnect authentication bypass — CVSS 10.0.",
            tags=("critical", "auth-bypass"),
            source_ref="https://nvd.nist.gov/vuln/detail/CVE-2024-1709",
        ),
        rec(
            source="nvd:default",
            type="cve",
            value="CVE-2023-44487",
            confidence=None,
            context="HTTP/2 Rapid Reset DDoS amplification — CVSS 7.5 high.",
            tags=("high", "dos", "http2"),
            source_ref="https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
        ),
        rec(
            source="nvd:default",
            type="cve",
            value="CVE-2024-6387",
            confidence=None,
            context="OpenSSH regreSSHion race condition RCE — CVSS 8.1 high. "
            "Unauthenticated RCE as root on glibc-based Linux.",
            tags=("high", "rce", "openssh"),
            source_ref="https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        ),
        rec(
            source="nvd:default",
            type="cve",
            value="CVE-2024-23897",
            confidence=None,
            context="Jenkins arbitrary file read via CLI — CVSS 9.8 critical.",
            tags=("critical", "file-read", "jenkins"),
            source_ref="https://nvd.nist.gov/vuln/detail/CVE-2024-23897",
        ),
        rec(
            source="otx:default",
            type="cve",
            value="CVE-2021-44228",
            confidence=None,
            context="Log4Shell — CVSS 10.0. Still actively exploited in the wild.",
            tags=("critical", "rce", "log4j", "itw"),
            age_hours=72,
        ),
        rec(
            source="rss:sans_isc",
            type="cve",
            value="CVE-2024-49113",
            confidence=None,
            context="Windows LDAP DoS — CVSS 7.5. PoC public, patch now.",
            tags=("high", "dos", "windows", "ldap"),
            age_hours=36,
        ),
    ]


if __name__ == "__main__":
    main()
