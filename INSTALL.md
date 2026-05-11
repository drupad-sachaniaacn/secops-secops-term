# SecOps Terminal — Installation Guide

> **v0.6.0** · Python 3.14+ · Windows / macOS / Linux

---

## How to get the wheel file

The wheel (`secops_term-0.6.0-py3-none-any.whl`) is the release artifact.
Build it once, distribute it to the team.

```powershell
# From the repo root (maintainer machine, one-time per release):
cd C:\path\to\AutoTUI
.venv\Scripts\python -m build --wheel
# Output: dist\secops_term-0.6.0-py3-none-any.whl
```

Then pick one of the three distribution methods below.

---

## Method A — Shared drive / Teams file share (simplest)

1. Copy `dist\secops_term-0.6.0-py3-none-any.whl` to a shared location
   (Teams Files tab, SharePoint, network share, OneDrive, etc.)

2. Each teammate downloads the file to their machine (e.g. `Downloads\`)

3. Install from the folder where the file was saved:

```powershell
# Open a terminal in the folder containing the .whl
cd "$env:USERPROFILE\Downloads"
pip install secops_term-0.6.0-py3-none-any.whl
```

> **Common mistake:** running `pip install .\dist\secops_term-0.6.0-py3-none-any.whl`
> only works from inside the AutoTUI repo root. Once the file is shared, install
> from wherever you downloaded it — no leading path needed if you `cd` there first.

---

## Method B — Internal PyPI server (best for ongoing rollouts)

Run this once on any machine the team can reach (your workstation, a jump box, a CI server):

```powershell
pip install pypiserver
pypi-server run -p 8080 C:\path\to\AutoTUI\dist
```

Teammates install from anywhere on the network — no file copy needed:

```powershell
pip install --extra-index-url http://HOSTNAME:8080/simple/ secops-term
```

Upgrading is then just:

```powershell
pip install --upgrade --extra-index-url http://HOSTNAME:8080/simple/ secops-term
```

> Replace `HOSTNAME` with the machine name or IP of the server running pypi-server.
> The `scripts\serve_packages.py` helper automates this (see below).

### Automated server script

```powershell
# Start the package server (keeps running until Ctrl+C):
python scripts\serve_packages.py

# Override host / port if needed:
python scripts\serve_packages.py --host 0.0.0.0 --port 9090
```

---

## Method C — Standalone executable (no Python required)

For machines that don't have Python installed:

```powershell
# Build a self-contained .exe (maintainer machine):
.venv\Scripts\pip install "secops-term[build]"
.venv\Scripts\python scripts\build_dist.py

# Result: dist\secops-term\secops-term.exe
# Zip the entire dist\secops-term\ folder and share it.
# No installer, no Python, no pip needed on the target machine.
```

---

## First-time setup (run once per machine, after installing)

```powershell
# Chronicle UDM Search
secops-term config chronicle

# Vision One (Trend Micro XDR)
secops-term config vision-one

# Intel providers — add whichever you have keys for
secops-term config intel otx          # AlienVault OTX
secops-term config intel virustotal   # VirusTotal Intelligence
secops-term config intel greynoise    # GreyNoise
secops-term config intel abuseipdb    # AbuseIPDB
secops-term config intel nvd          # NVD (no key required)
secops-term config intel abuse_ch     # abuse.ch feeds (no key required)

# Verify everything is wired up
secops-term doctor
```

Secrets are stored in the **OS keyring** (Windows Credential Manager on Windows,
macOS Keychain on macOS) — never written to disk in plain text.

---

## Daily use

```powershell
secops-term tui                        # full TUI — navigate with d/i/a/h/p/q/c/l
secops-term intel pull                 # pull fresh IOCs from all configured providers
secops-term intel list                 # browse the local IOC store
secops-term alerts ingest              # ingest alerts from Chronicle + Vision One
secops-term hunt enqueue --ioc-id N   # queue a retro hunt for an IOC
secops-term audit verify               # verify the hash-chained audit log
```

---

## Upgrading

```powershell
# Method A (wheel file) — download the new wheel, then:
pip install secops_term-0.6.1-py3-none-any.whl

# Method B (PyPI server) — from anywhere:
pip install --upgrade --extra-index-url http://HOSTNAME:8080/simple/ secops-term
```

Config and keyring secrets are preserved across upgrades.

---

## Uninstall

```powershell
pip uninstall secops-term

# Optionally remove local data (IOC store, config, audit log):
Remove-Item -Recurse "$env:USERPROFILE\.secops-term"   # Windows
rm -rf ~/.secops-term                                   # macOS / Linux
```

---

## System requirements

| Requirement | Minimum |
|---|---|
| Python | 3.14+ |
| OS | Windows 10+, macOS 13+, Ubuntu 22.04+ |
| Terminal | Windows Terminal, iTerm2, any ANSI-capable terminal |
| Keyring | Windows Credential Manager (built-in) |
| Network | HTTPS to configured SIEM/XDR endpoints and intel provider APIs |
