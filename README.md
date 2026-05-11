# SecOps Terminal

A keyboard-driven terminal UI for SOC engineers that sits **between your SIEM and your SOAR** — it does not replace either.

Connect it to Chronicle and/or Vision One, point it at your threat-intel feeds, and get a single pane of glass for pulling IOCs, triaging alerts, firing retro hunts, and running response playbooks — all from the terminal, all audit-logged.

---

## What it does

### Threat intelligence
- Pulls IOCs from **7 providers** in one command: AlienVault OTX, abuse.ch (ThreatFox / URLhaus / MalwareBazaar / Feodo Tracker), VirusTotal Intelligence, GreyNoise, AbuseIPDB, NVD CVEs, and any RSS/Atom feed
- Stores everything in a local SQLite database — search, filter by type, and export at any time
- Exports your entire IOC store (or a filtered subset) as a **STIX 2.1 bundle** for sharing with other tools

### Alert triage
- Ingests alerts from **Chronicle, Vision One, and Deep Security** in one pass
- Deduplicates and normalises across sources so you see one card per incident, not three
- Grouped view shows alert clusters by title + source + entity

### Retro hunts
- Queue a retro hunt for any IOC with one command
- Runs UDM Search (Chronicle) or Vision One queries in the background
- Results surface in the TUI as they complete

### Playbooks
- Define response workflows in YAML — no code required
- Steps support HTTP calls, CLI commands, retro hunts, and notifications
- Dry-run mode, per-step timeouts, retry budgets, and full audit trail built in
- Notify via **Slack**, **Teams**, or any webhook

### AI-assisted queries
- Describe what you want in plain English — get a UDM Search or TMV1 Search query back
- Works with Claude via clipboard (no API key required), headless CLI, or MCP server
- AI output is display-only; it never drives automated actions

### TUI screens
Navigate with single key presses:

| Key | Screen | What you do there |
|-----|--------|-------------------|
| `d` | Dashboard | At-a-glance counts: IOCs, hunt queue, configured providers |
| `i` | Intel | Browse and search the local IOC store |
| `a` | Alerts | Triage ingested alerts, toggle grouped view |
| `h` | Retro Hunts | Monitor the hunt queue, see hits and errors |
| `p` | Playbooks | List, inspect, and run response playbooks |
| `q` | Query | Natural-language → UDM / TMV1 query translation |
| `c` | Config | Configured providers and live health checks |
| `l` | Audit Log | Browse and verify the tamper-evident audit log |

---

## Install

Get the `.whl` from whoever manages releases, download it, then install from the folder you saved it to:

```powershell
cd "$env:USERPROFILE\Downloads"
pip install secops_term-0.6.0-py3-none-any.whl
```

For team-wide rollouts, a one-liner internal PyPI server lets everyone install and upgrade without file copying:

```powershell
# On the server / maintainer machine:
pip install pypiserver
python scripts\serve_packages.py      # serves dist\ on port 8080

# Teammates (from anywhere on the network):
pip install --extra-index-url http://HOSTNAME:8080/simple/ secops-term
```

See [`INSTALL.md`](INSTALL.md) for all three distribution methods and the standalone `.exe` build.

Requires Python 3.14 or later.

---

## First-time setup

Run the config wizard once for each service you want to connect. Everything is interactive — no config files to hand-edit, no environment variables.

```powershell
# Your SIEM / XDR
secops-term config chronicle      # Chronicle UDM Search
secops-term config vision-one     # Trend Micro Vision One
secops-term config intel otx      # AlienVault OTX (needs API token)
secops-term config intel greynoise    # GreyNoise (needs API key)
secops-term config intel abuseipdb    # AbuseIPDB (needs API key)
secops-term config intel virustotal   # VirusTotal Intelligence (needs API key)
secops-term config intel nvd          # NVD CVEs (no key required)
secops-term config intel abuse_ch     # abuse.ch feeds (no key required)

# Verify everything is working
secops-term doctor
```

API keys are stored in the **OS keyring** (Windows Credential Manager on Windows, macOS Keychain on macOS) — never written to disk in plain text.

---

## Daily use

**Launch the TUI** (recommended for most workflows):
```powershell
secops-term tui
```

**Pull fresh threat intel from all configured providers:**
```powershell
secops-term intel pull
secops-term intel pull --provider otx          # one provider only
secops-term intel pull --since 2024-06-01      # only new since a date
```

**Search your IOC store:**
```powershell
secops-term intel list
secops-term intel list --type ipv4
secops-term intel list --search 185.220.101
```

**Ingest alerts:**
```powershell
secops-term alerts ingest
secops-term alerts ingest --provider chronicle
```

**Queue and run retro hunts:**
```powershell
secops-term hunt enqueue --ioc-id 42 --platform chronicle
secops-term hunt drain --platform chronicle --max 10
secops-term hunt status
```

**Run a playbook:**
```powershell
secops-term playbooks list
secops-term playbooks run high-conf-ioc-followup --dry-run
secops-term playbooks run high-conf-ioc-followup --ioc-id 42
```

**Export IOCs as STIX 2.1:**
```powershell
secops-term intel export --format stix
secops-term intel export --format stix --type cve --out cves.json
```

**Translate a question into a search query:**
```powershell
secops-term ai query --target udm "show me lateral movement from 10.0.0.0/8 in the last 7 days"
secops-term ai query --target tmv1 "emails with suspicious attachments from external senders"
```

---

## Threat-intel providers

| Provider | What you get | Key required |
|----------|-------------|--------------|
| `otx` | IPs, domains, URLs, hashes, CVEs from AlienVault OTX pulses | Yes — OTX API token |
| `abuse_ch` | Malware hashes (MalwareBazaar), malicious URLs (URLhaus), IPs (Feodo, ThreatFox) | Yes — abuse.ch token |
| `virustotal` | Malware file hashes from VT Intelligence | Yes — VT API key (Intelligence tier) |
| `greynoise` | Malicious IPs from GreyNoise GNQL | Yes — GreyNoise API key |
| `abuseipdb` | High-confidence malicious IPs from AbuseIPDB blacklist | Yes — AbuseIPDB API key |
| `nvd` | CVEs above a configurable CVSS v3 threshold | No — public API |
| `rss` | IOCs extracted from any RSS/Atom feed (BleepingComputer, Krebs, SANS ISC, etc.) | No |

Configure any provider with:
```powershell
secops-term config intel PROVIDER
```

Test a provider's connectivity at any time:
```powershell
secops-term config test-all
secops-term config test otx
```

---

## Playbooks

Playbooks are YAML files in `~/.secops-term/playbooks/`. Three example playbooks are included:

| Playbook | What it does |
|----------|-------------|
| `daily-feed-pull` | Pull intel from all providers, notify Slack with a summary |
| `high-conf-ioc-followup` | Enqueue retro hunts on Chronicle and Vision One for a high-confidence IOC |
| `weekly-osint-roundup` | Pull from RSS providers, export STIX bundle, post to Teams |

Run `secops-term playbooks init` to copy the examples into your data directory and start customising.

---

## Audit log

Every action — intel pulls, alert ingests, playbook runs, config changes — is appended to a hash-chained JSONL audit log at `~/.secops-term/audit.jsonl`.

The chain means tampering with any past entry breaks verification:

```powershell
secops-term audit verify         # walks the full chain and reports OK or the first break
```

The log is also browsable in the TUI (`l` key).

---

## Requirements

| | Minimum |
|---|---|
| Python | 3.11+ |
| OS | Windows 10 / 11, macOS 13+, Ubuntu 22.04+ |
| Terminal | Windows Terminal, iTerm2, or any ANSI-capable terminal |
| Keyring | Windows Credential Manager (built-in), macOS Keychain (built-in) |

---

## Upgrading

```powershell
pip install --upgrade secops-term
```

Config and keyring secrets are preserved across upgrades.

---

## For contributors and maintainers

See [`INSTALL.md`](INSTALL.md) for wheel builds, PyInstaller packaging, and corporate PyPI publishing.
See [`DECISIONS.md`](DECISIONS.md) for the architectural design log.

---

## License

MIT. See `LICENSE`.
