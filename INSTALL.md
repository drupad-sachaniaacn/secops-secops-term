# SecOps Terminal — Installation Guide

> **v0.6.0** · Python 3.11 + · Windows / macOS / Linux

---

## Quick install (team standard)

```powershell
pip install secops-term
```

Or from a wheel file shared by the team:

```powershell
pip install secops_term-0.6.0-py3-none-any.whl
```

Or directly from the corporate git repo:

```powershell
pip install git+https://your-corp-git.example.com/secops/secops-term.git
```

That is all. No `git clone`, no virtual environment setup, no config files to hand-edit.

---

## First-time setup (run once per machine)

After `pip install`, run the interactive config wizard for each service you use:

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
macOS Keychain on macOS) — never in files on disk.

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
pip install --upgrade secops-term

# Or from a new wheel file:
pip install --upgrade secops_term-0.6.1-py3-none-any.whl
```

Your config and keyring secrets are preserved across upgrades.

---

## Uninstall

```powershell
pip uninstall secops-term

# Optionally remove local data (IOC store, config, audit log):
Remove-Item -Recurse "$env:USERPROFILE\.secops-term"   # Windows
rm -rf ~/.secops-term                                   # macOS / Linux
```

---

## Building a release wheel (maintainers only)

```powershell
# From the repo root, with dev deps installed:
pip install build
python -m build

# Produces:
#   dist/secops_term-0.6.0-py3-none-any.whl   ← share this with the team
#   dist/secops_term-0.6.0.tar.gz              ← source archive
```

Upload to your corporate PyPI:

```powershell
pip install twine
twine upload --repository-url https://your-corp-pypi/simple/ dist/*
```

Or drop the `.whl` on a shared drive / Teams / internal artifact store.

---

## Building a standalone binary (no Python required)

For machines without Python installed, build a self-contained executable:

```powershell
pip install "secops-term[build]"
python scripts/build_dist.py

# Result: dist\secops-term\secops-term.exe (Windows)
# Zip and distribute — no installer, no Python, no pip needed.
```

---

## System requirements

| Requirement | Minimum |
|---|---|
| Python | 3.11+ |
| OS | Windows 10+, macOS 13+, Ubuntu 22.04+ |
| Terminal | Windows Terminal, iTerm2, any ANSI-capable terminal |
| Keyring | Windows Credential Manager (built-in) |
| Network | HTTPS to configured SIEM/XDR endpoints and intel provider APIs |
