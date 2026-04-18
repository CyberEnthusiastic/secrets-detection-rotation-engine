# Secrets Detection &amp; Rotation Engine

> **Find hardcoded secrets in code + git history, then auto-generate a provider-specific rotation runbook - 17 providers, entropy-aware, zero dependencies.**
> A free, self-hosted alternative to Gitleaks Cloud, Trufflehog Enterprise, and GitGuardian for teams that want secret-detection plus a rotation playbook without the enterprise price tag.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Providers](https://img.shields.io/badge/providers-17-A14241)](./engine.py)

---

## What it does (in one screenshot of terminal output)

```
============================================================
  Secrets Detection & Rotation Engine v1.0
============================================================
[*] Total secrets  : 8
[*] By severity    : {'CRITICAL': 3, 'HIGH': 4, 'MEDIUM': 1, 'LOW': 0}
[*] By provider    : {'aws':1, 'github':1, 'openai':1, 'slack':1, 'google':1, 'generic':3}

[CRITICAL] GitHub PAT (classic)   samples/leaky_config.py:10 (entropy=5.17, risk=87.0)
   > ghp_1234567890abcdefghijklmnopqrstuvwxyz

[HIGH] OpenAI API Key             samples/leaky_config.py:13 (entropy=5.34, risk=79.0)
   > sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPqrstuv

[CRITICAL] AWS Access Key ID      samples/leaky_config.py:6 (entropy=1.5, risk=77.0)
   > AKIAIOSFODNN7EXAMPLE

[HIGH] Database URL with embedded password
   samples/leaky_config.py:22 (entropy=4.39, risk=75.9)
   > postgres://app:SuperSecret2025!@db.prod.example:5432/appdb
```

And generates a **rotation runbook** per provider:

```
[AWS] 1 secret(s)
  1. Inventory who uses this key (CloudTrail LookupEvents).
  2. Create a NEW IAM access key.
  3. Deploy the new key to your secret manager.
  4. Update app config, redeploy.
  5. Monitor CloudTrail to confirm only the new key is in use.
  6. Inactivate the old key.
  7. Wait 7 days watching for stragglers.
  8. Delete the old key.
```

Plus an interactive dark-mode HTML dashboard (severity chips, provider pills, per-finding drill-down).

---

## Screenshots (ran locally, zero setup)

**Terminal output** - exactly what you see on the command line:

![Terminal output](docs/screenshots/terminal.png)

**Interactive HTML dashboard** - opens in any browser, dark-mode, filterable:

![HTML report](docs/screenshots/report.png)

Both screenshots are captured from a real local run against the bundled `samples/` directory. Reproduce them with the quickstart commands below.

---

## Why you want this

| | **This engine** | Gitleaks | Trufflehog | GitGuardian |
|---|---|---|---|---|
| **Price** | Free (MIT) | Free (OSS) + paid cloud | Free (OSS) + paid | SaaS |
| **Runtime deps** | **None** - pure stdlib | Go binary | Go binary | SaaS |
| **Provider coverage** | 17 rules | 100+ | 800+ | Curated |
| **Entropy + pattern hybrid** | Yes | Yes | Yes | Yes |
| **Git history scan** | Yes | Yes | Yes | Yes |
| **Rotation runbook per provider** | Yes | No | No | Partial |
| **HTML report w/ drill-down** | Bundled | No | No | Dashboard |
| **Self-hosted / air-gapped** | Yes | Yes | Yes | No |
| **Extend with Python** | 10 lines | Regex + TOML | Go + YAML | No |

---

## 60-second quickstart

```bash
# 1. Clone
git clone https://github.com/CyberEnthusiastic/secrets-detection-rotation-engine.git
cd secrets-detection-rotation-engine

# 2. Scan the included samples (zero install - pure Python 3.8+ stdlib)
python engine.py scan samples/

# 3. Open the HTML report
start reports/secrets_report.html      # Windows
open  reports/secrets_report.html      # macOS
xdg-open reports/secrets_report.html   # Linux
```

### Scan your own code or git history

```bash
# A single file
python engine.py scan src/config.py

# A whole repo (skips .git, node_modules, .venv, etc.)
python engine.py scan .

# Every commit in git history (catches secrets that were later removed)
python engine.py git /path/to/your/repo

# Generate a rotation runbook from a findings JSON
python engine.py rotate reports/secrets_report.json
```

### Alternative: one-command installer

```bash
./install.sh        # Linux/Mac/WSL/Git Bash
.\install.ps1       # Windows PowerShell
```

---

## What it detects (17 providers)

| ID | Provider | Example |
|----|----------|---------|
| AWS-AKID | AWS | Access Key ID (AKIA / ASIA / AROA...) |
| AWS-SECRET | AWS | Secret Access Key (40-char b64) |
| GH-PAT | GitHub | Classic PAT `ghp_...` |
| GH-PAT-FG | GitHub | Fine-grained PAT `github_pat_...` |
| GH-OAUTH | GitHub | OAuth token `gho_...` |
| SLACK-BOT | Slack | Bot / User token `xox[baprs]-...` |
| OPENAI | OpenAI | `sk-` API key |
| GCP-SVC | Google Cloud | Service account JSON key |
| GOOGLE-API | Google | API key `AIza...` |
| PEM-KEY | Generic | RSA / EC / OpenSSH private key block |
| STRIPE | Stripe | `sk_live` / `sk_test` / `rk_live` |
| TWILIO | Twilio | Account SID `AC<hex>` |
| SENDGRID | SendGrid | `SG.<id>.<secret>` |
| JWT | Generic | JSON Web Tokens |
| GENERIC-PW | Generic | Hardcoded `password=...` |
| BEARER | Generic | `Authorization: Bearer ...` |
| DATABASE-URL | Generic | `postgres://user:pw@host/db` |

Plus an **allowlist heuristic** that ignores markers like `placeholder`, `YOUR-KEY-HERE`, `replace-me`, `test-only-*` so obvious test values don't flood the report.

---

## How the risk scorer works

`risk_score()` blends signals to produce a 0-100 score per finding:

- **Base confidence** (base 60) - each rule ships with 0.85-0.95 confidence
- **Severity bonus** - +20 CRITICAL, +12 HIGH, +6 MEDIUM
- **Shannon entropy bonus** - up to +10 for high-entropy matches (weeds out low-entropy false positives like `password=password`)
- **Git history bonus** - +5 if the secret shows up in a historical commit (still leaked even if currently removed)

---

## Rotation runbook (built-in, per provider)

Run the rotation planner against the output of `scan` or `git` to get a provider-specific playbook:

```
$ python engine.py rotate reports/secrets_report.json
============================================================
  Rotation Plan
============================================================

[AWS]  1 secret(s)
  1. Inventory usage (CloudTrail LookupEvents for last 30 days).
  2. aws iam create-access-key --user-name <user>
  3. Deploy new key to Secrets Manager / Vault / Doppler.
  4. Update app config, redeploy.
  5. Monitor CloudTrail for old-key usage.
  6. aws iam update-access-key --status Inactive
  7. Wait 7 days.
  8. aws iam delete-access-key

[GITHUB]  2 secret(s)
  1. Identify scopes (github.com/settings/audit).
  2. Create replacement with minimum scope + 90d expiry.
  3. Update secret in Actions + CI + local dev.
  4. Revoke leaked token.
  5. Audit actions taken with old token.

[OPENAI]  1 secret(s)
  1. platform.openai.com/account/api-keys
  2. Create new key; copy.
  3. Replace secret; redeploy.
  4. Delete leaked key.
  5. Review usage dashboard for last 7 days.

... (Slack, Stripe, Google, Twilio, SendGrid, GCP, generic)
```

---

## Git-history scanning

```bash
python engine.py git .
```

Walks `git log --all -p -U0` and runs every rule against every added line across every commit. Catches the classic "I committed the secret, noticed, then amended it away" leak.

For a clean history, the recommended post-remediation step is:

```bash
git filter-repo --replace-text sensitive-text.txt
# or use BFG Repo-Cleaner for large histories
git push --force --tags origin 'refs/heads/*'
```

---

## CI/CD integration (block merges on CRITICAL findings)

```yaml
- name: Scan for secrets
  run: python engine.py scan .

- name: Fail on CRITICAL
  run: |
    python -c "
    import json, sys
    r = json.load(open('reports/secrets_report.json'))
    if r['summary']['by_severity']['CRITICAL'] > 0:
        print('CRITICAL secrets detected in repo')
        sys.exit(1)
    "
```

---

## Extending the rule engine

Add to `SECRET_RULES`:

```python
{
    "id": "DISCORD-BOT", "name": "Discord Bot Token",
    "pattern": r"\bM[A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b",
    "severity": "HIGH", "entropy_min": 3.8, "provider": "discord",
    "rotate_doc": "discord.com/developers/applications -> reset token",
},
```

Then optionally add rotation steps to `ROTATION_STEPS["discord"]`.

---

## Project layout

```
secrets-detection-rotation-engine/
|-- engine.py              # scanner + git walker + rotation planner + CLI
|-- report_generator.py    # dark-mode HTML report
|-- samples/
|   |-- leaky_config.py
|   `-- clean_config.py
|-- reports/               # output (gitignored)
|-- Dockerfile
|-- install.sh / install.ps1
|-- requirements.txt       # empty - pure stdlib
|-- README.md
`-- LICENSE / NOTICE / SECURITY.md / CONTRIBUTING.md
```

---

## Roadmap

- [ ] Verified-leak mode (query provider API to confirm key is live)
- [ ] Webhook to page on-call when a CRITICAL is found in git history
- [ ] Vault / AWS Secrets Manager / Doppler auto-rotation
- [ ] Pre-commit hook / Husky integration
- [ ] JetBrains plugin + VS Code extension

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Security

Responsible disclosure policy: see [SECURITY.md](./SECURITY.md).

---

Built by **[Mohith Vasamsetti (CyberEnthusiastic)](https://github.com/CyberEnthusiastic)** as part of the [AI Security Projects](https://github.com/CyberEnthusiastic?tab=repositories) suite.
