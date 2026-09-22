# Privacy Center

Local-first toolkit for auditing your own public digital footprint. It performs passive public checks only, never logs in to discovered accounts, never downloads breach dumps, and never deletes anything.

## What it does

- Audits username, email and GitHub exposure using passive public checks.
- Inspects metadata in JPG, PNG, PDF, DOCX and MP4 files.
- Creates sanitized copies while preserving the original files.
- Reviews local MBOX and EML exports for account-registration messages.
- Presents summary counts in a token-protected local dashboard.
- Includes GDPR request templates and optional 30-day recheck units.

## Install

Python 3.11 or newer is recommended. ExifTool is required for metadata commands;
qpdf is optional and improves PDF rewriting.

```bash
git clone https://github.com/tilemachoscfu/privacy-center.git ~/privacy-center
cd ~/privacy-center
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp config/identity.example.yml config/identity.yml
cp data/accounts.example.csv data/accounts.csv
cp data/data-brokers.example.csv data/data-brokers.csv
chmod 600 config/identity.yml data/accounts.csv data/data-brokers.csv
```

Optionally install Sherlock and Maigret into isolated environments under
`tools/sherlock` and `tools/maigret`. The related checks are skipped when those
executables are absent.

## Commands

```bash
privacy-audit username exampleuser
privacy-audit email user@example.com
privacy-audit github
privacy-audit metadata ~/Photos
privacy-audit metadata-sanitize ~/Photos/example.jpg
privacy-audit email-export ~/Exports/mail.mbox
privacy-audit dashboard
privacy-audit all
```

Add identifiers only to `config/identity.yml` (mode 0600). For Have I Been Pwned, supply your own legitimate API key only for one process: `HIBP_API_KEY=... privacy-audit email you@example.com`. The key is not stored.

Username findings are heuristic and require manual confirmation. A claimed username is not proof that the account belongs to you.

The dashboard binds to the detected private LAN address, uses a random token stored with mode 0600, and displays summary counts only. Use `--bind 127.0.0.1` for localhost-only operation.

The systemd timer files are examples only and are not installed or enabled.

## Privacy boundaries

The repository intentionally excludes identity configuration, dashboard tokens,
audit results, account and data-broker trackers, sanitized output, local tools
and virtual environments. Read [SECURITY.md](SECURITY.md) before running an
audit or sharing generated output.
