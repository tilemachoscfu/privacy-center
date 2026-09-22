# Security

Privacy Center is designed for authorized audits of your own accounts, exports
and files. Do not use it to access accounts or data that you do not own or have
permission to inspect.

## Data handling

- Keep `config/identity.yml`, `results/`, `sanitized/` and the runtime dashboard
  token private. They are excluded from version control.
- Supply `HIBP_API_KEY` only through the current process environment. Never add
  it to configuration files or commits.
- Review generated reports before sharing them. They may contain identifiers,
  file paths, profile URLs or other personal information.
- Metadata sanitization creates copies. Preserve original files separately.

## Reporting a vulnerability

Open a GitHub security advisory or contact the maintainer privately. Do not
include real identifiers, audit reports, credentials or personal files in a
public issue.
