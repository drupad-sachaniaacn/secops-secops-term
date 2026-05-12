# Team Access Guide

How to give a colleague access, how they connect, and how secrets flow in.

---

## Step 1 — Add them to the repo (maintainer, one-time per person)

1. Go to the repo on GitHub → **Settings → Collaborators and teams**
2. Click **Add people**, enter their GitHub username
3. Set role to **Write** (they can push branches) or **Read** (review only)
4. They get an email invite — they must accept it

That is all they need. Repo access automatically grants Codespace access.

---

## Step 2 — Set up Infisical secrets (maintainer, one-time per repo)

Do this once. Every Codespace that opens after this will have the secrets automatically.

1. In the repo on GitHub → **Settings → Secrets and variables → Codespaces**
2. Add the following secrets:

| Secret name | What to put in it |
|-------------|------------------|
| `INFISICAL_TOKEN` | Service token from your Infisical project |
| `INFISICAL_PROJECT_ID` | Project ID from Infisical (Settings → Project ID) |
| `INFISICAL_ENVIRONMENT` | Environment slug, e.g. `production` |
| `INFISICAL_HOST` | Only needed if self-hosted, e.g. `https://infisical.corp.example.com` — leave blank for cloud |

These are **repository-level secrets** — they are never visible to users, never stored in any file, and GitHub injects them as environment variables only inside Codespaces for this repo.

---

## Step 3 — Set up connector secrets in Infisical (maintainer, one-time)

In the Infisical dashboard, create one secret per connector credential. Use these exact names:

| Connector | Infisical secret name |
|-----------|----------------------|
| Chronicle service account JSON | `SECOPS_TERM__CHRONICLE__DEFAULT__SERVICE_ACCOUNT_JSON` |
| Vision One API token | `SECOPS_TERM__VISION_ONE__DEFAULT__API_TOKEN` |
| AlienVault OTX | `SECOPS_TERM__OTX__DEFAULT__API_TOKEN` |
| VirusTotal | `SECOPS_TERM__VIRUSTOTAL__DEFAULT__API_KEY` |
| GreyNoise | `SECOPS_TERM__GREYNOISE__DEFAULT__API_KEY` |
| AbuseIPDB | `SECOPS_TERM__ABUSEIPDB__DEFAULT__API_KEY` |
| abuse.ch | `SECOPS_TERM__ABUSE_CH__DEFAULT__API_TOKEN` |

The pattern is always: `SECOPS_TERM__{PROVIDER}__{INSTANCE}__{FIELD}` in uppercase.

---

## How a teammate connects (their steps, after being invited)

### Option A — Browser (zero install)

1. Go to the repo on GitHub
2. Press `.` (full stop) — or click the **Code** button → **Codespaces** → **Create codespace on main**
3. A VS Code environment opens in the browser
4. Open the terminal (`Ctrl+\`\``) and run:
   ```bash
   secops-term tui
   ```
5. Infisical credentials are already present — no config wizard needed

### Option B — SSH from their local machine

Install the GitHub CLI once:
```bash
# macOS
brew install gh

# Windows
winget install GitHub.cli
```

Then:
```bash
gh auth login                          # once — logs in with their GitHub account
gh cs create --repo YOUR-ORG/secops-term --machine basicLinux32gb
gh cs ssh                              # drops them into the Codespace shell
secops-term tui
```

### Option C — VS Code desktop

1. Install the **GitHub Codespaces** VS Code extension
2. Open Command Palette → **Codespaces: Connect to Codespace**
3. Open the integrated terminal and run `secops-term tui`

---

## What happens automatically when a Codespace opens

The `postCreateCommand` in `.devcontainer/devcontainer.json` runs once:

```bash
pip install -e '.[dev]' && secops-term doctor
```

- Installs the tool and all dependencies
- Runs `secops-term doctor` which checks every connector and prints a health table
- Because `INFISICAL_TOKEN` and `INFISICAL_PROJECT_ID` are present, the tool uses
  Infisical as its secrets backend automatically — no `secops-term config` wizard needed

---

## What the private repo means for access

| Action | Requires |
|--------|---------|
| Open a Codespace | GitHub repo Collaborator access |
| SSH into a Codespace | GitHub CLI + repo Collaborator access |
| Access connector API keys | Nothing extra — Infisical serves them via the machine token |
| Contribute code / open PRs | Write access (set when adding as Collaborator) |

The private repo and the SSH access are the **same gate**. There is no separate SSH key to distribute, no VPN, no second password. If someone can see the repo on GitHub, they can open a Codespace and run the tool.

---

## Revoking access

1. Repo → **Settings → Collaborators** → remove the person
2. Their Codespace will stop working immediately on next auth check
3. The Infisical machine token is shared (not per-user) — if you need per-user
   audit trails at the Infisical level, create a separate machine identity per person
   and distribute tokens as individual Codespace **user** secrets rather than repo secrets

---

## Codespace sizes

The default (`basicLinux32gb`) is fine for the TUI. If running the full test suite:

```bash
gh cs create --repo YOUR-ORG/secops-term --machine standardLinux32gb
```

---

## Troubleshooting

**`secops-term: command not found`**  
The `postCreateCommand` may not have finished. Run manually:
```bash
pip install -e '.[dev]'
```

**`INFISICAL_TOKEN not set` or secrets returning None**  
Check that the Codespace secrets were added at the **repository** level (not user level) in GitHub settings. Restart the Codespace after adding them.

**`secops-term doctor` shows a connector as FAIL**  
The secret name in Infisical may not match the expected pattern. Check the table in Step 3 above.
