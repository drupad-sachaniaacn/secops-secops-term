# SecOps Terminal

A navigational terminal UI for security operations engineers. Sits between a SIEM and a SOAR — does **not** replace either.

Pulls threat intel, fires retro hunts in Chronicle and Vision One, surfaces consolidated alert cards, runs YAML-defined playbooks, translates natural language to UDM Search / TMV1 Search queries, and exports IOCs as STIX 2.1 bundles.

> **Status:** v0.6.0 — all six phases complete. See `DECISIONS.md` for the running design log.

## Feature summary

| Phase | Features |
|-------|----------|
| 0 | Security primitives: Argon2id-Fernet keyring, hash-chained JSONL audit log, ACL-enforced data root, SSRF guard, URL allow-list, taint+redact registry |
| 1 | Threat-intel pipeline: OTX, abuse.ch (4 sub-feeds), RSS/Atom + article scraping, IOC store (SQLite), provider registry, health checks |
| 2 | Retro hunts: Chronicle UDM search, Vision One, retro-hunt worker + job queue, RetroHunts TUI screen |
| 3 | Unified alerts: Chronicle + Vision One + Deep Security ingestion, normalize/dedup, Alerts TUI screen |
| 4 | AI Bridge: headless Claude CLI transport, clipboard transport, optional MCP server (loopback + bearer + rate-limit), NLP → UDM / TMV1 query generation, Query TUI screen |
| 5 | Playbooks: Pydantic schema, YAML loader, sandbox engine (retry/timeout/audit/dry-run), 3 notifiers (generic_json/slack/teams), Playbooks TUI screen |
| 6 | Polish: VirusTotal + GreyNoise + AbuseIPDB + NVD intel providers, STIX 2.1 bundle export (`intel export --format stix`), PyInstaller distributable builds |

## Hard rules

- **No environment variables for secrets or environment-specific URLs.** All sensitive values live in OS keyring (with an Argon2id-Fernet fallback). All non-secret config lives in `~/.secops-term/config.toml` with restrictive ACLs.
- **Read-mostly by default.** Destructive actions require an explicit `allow_write` toggle plus an interactive confirm.
- **Every input is adversarial.** Scraped content, RSS feeds, and AI bridge outputs never drive automated control flow.
- **TLS always verified.** No `--insecure` flag exists.
- **AI output is display-only.** AI-generated text never drives `when:` expressions or write-step parameters in playbooks (brief §7.5).

## Install (development)

This project targets Python 3.11+. Recommended dev workflow uses [`uv`](https://docs.astral.sh/uv/).

```powershell
# Clone, then from the repo root:
uv venv
.venv\Scripts\Activate.ps1            # Windows PowerShell
uv pip install -e ".[dev]"
uv pip compile pyproject.toml -o requirements.lock
```

On macOS / Linux:

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
uv pip compile pyproject.toml -o requirements.lock
```

## First run

After install, the entry point is `secops-term`:

```powershell
secops-term --help
secops-term doctor          # health checks across configured providers
secops-term config          # interactive wizard (Chronicle, Vision One, Deep Security, intel, notifiers)
secops-term audit verify    # walk the hash-chained audit log
secops-term tui             # launch the Textual TUI
```

The first run creates `~/.secops-term/` with `0o600` (POSIX) / restricted-ACL (Windows) permissions. `doctor` refuses to start if those permissions are wrong.

## CLI surface

```
secops-term intel pull [--provider NAME] [--since YYYY-MM-DD]
secops-term intel list [--type TYPE] [--limit N] [--search SUBSTR]
secops-term intel export --format stix [--type TYPE] [--out FILE]

secops-term alerts ingest [--provider chronicle|vision_one|deep_security]

secops-term playbooks list
secops-term playbooks show NAME
secops-term playbooks init [--force]
secops-term playbooks run NAME [--dry-run] [--ioc-id N]

secops-term hunt enqueue --ioc-id N --platform chronicle|vision_one
secops-term hunt drain [--platform NAME] [--max N]
secops-term hunt status

secops-term ai query --target udm|tmv1 QUESTION
secops-term ai status

secops-term config show
secops-term config test PROVIDER
secops-term config test-all
secops-term config chronicle
secops-term config vision-one
secops-term config intel PROVIDER [--instance NAME]

secops-term audit verify
secops-term doctor
secops-term version
```

## Threat-intel providers

| Provider | IOC types | Auth | Health probe |
|----------|-----------|------|-------------|
| `otx` | ipv4, ipv6, domain, url, sha256, sha1, md5, email, cve | Keyring `api_token` | `GET /users/me` (quota-free) |
| `abuse_ch` | url, sha256, sha1, md5, ipv4 | Keyring `api_token` | ThreatFox `get_iocs` (1 day) |
| `rss` | all types (IOC extraction) | None (feed URL in config) | Feed fetch + feedparser |
| `virustotal` | sha256, sha1, md5 | Keyring `api_key` | `GET /api/v3/users/{owner}` (quota-free) |
| `greynoise` | ipv4 | Keyring `api_key` | `GET /ping` |
| `abuseipdb` | ipv4 | Keyring `api_key` | `GET /api/v2/check?ipAddress=8.8.8.8` |
| `nvd` | cve | Keyring `api_key` (optional) | `GET /rest/json/cves/2.0?resultsPerPage=1` |

## STIX 2.1 export

```powershell
# Export all IOCs as a STIX 2.1 bundle to stdout:
secops-term intel export --format stix

# Export only CVEs to a file:
secops-term intel export --format stix --type cve --out bundle.json

# Pipe to jq for inspection:
secops-term intel export --format stix | jq '.objects[].type' | sort | uniq -c
```

IOC → STIX object mapping: ipv4→`ipv4-addr`, ipv6→`ipv6-addr`, domain→`domain-name`, url→`url`, sha256/sha1/md5→`file`, email→`email-addr`, cve→`vulnerability`. IDs are deterministic UUIDv5 (STIX namespace `00abedb4-aa42-466c-9c01-fed23315a9b7`) so the same IOC always produces the same STIX ID across exports.

## Distributable builds (PyInstaller)

Requires the `[build]` optional extra:

```bash
pip install "secops-term[build]"
python scripts/build_dist.py
```

The bundle lands at `dist/secops-term/`. The entry point binary is:

| Platform | Binary path |
|----------|-------------|
| Windows  | `dist\secops-term\secops-term.exe` |
| macOS    | `dist/secops-term/secops-term` |
| Linux    | `dist/secops-term/secops-term` |

Build on the target platform — PyInstaller does not cross-compile. See `scripts/build_dist.py` and `secops_term.spec` for platform-specific signing notes.

## Quality gates

```powershell
ruff check .
ruff format --check .
mypy secops_term
pytest                              # unit + integration tests (968 tests)
pytest -m security                  # security-primitive tests (separate CI job)
pytest --cov=secops_term            # coverage
```

Coverage targets:
- `core/url_guard.py`, `core/audit.py`, `playbooks/sandbox.py`, `core/secrets.py`, `core/redact.py` — **100%**.
- Other `core/`, `intel/`, `playbooks/` — **>= 70%**.

## Project layout

```
secops_term/
├── core/           # primitives: paths, secrets, audit, db, health, redact, url_guard, registry
├── intel/          # providers (7), store, scraper, ioc, orchestrator, stix_export
│   └── providers/  # otx, abuse_ch, rss, virustotal, greynoise, abuseipdb, nvd
├── notifications/  # generic_json, slack, teams, orchestrator
├── playbooks/      # schema, loader, engine, runners, sandbox, examples/
├── alerts/         # normalize, dedup, ingest, types
├── ai/             # bridge, clipboard, audit, selector, nlp_prompts, nlp_validators, nlp_query
├── mcp/            # gate, tools, server (MCP Transport B)
├── chronicle/      # client, factory, query_builder, retro_hunt
├── trendmicro/     # vision_one, deep_security, factory
├── ui/
│   └── screens/    # DashboardScreen (stub), IntelScreen, RetroHuntsScreen,
│                   # AlertsScreen, QueryScreen, PlaybooksScreen, ConfigScreen (stub)
└── cli.py          # Typer entry point
scripts/
└── build_dist.py   # PyInstaller build helper
secops_term.spec    # PyInstaller spec (directory-mode bundle)
tests/              # 968 tests, mirrors secops_term/ structure
DECISIONS.md        # running design log
```

## License

MIT. See `LICENSE`.
