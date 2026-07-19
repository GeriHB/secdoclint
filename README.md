# SecDocLint

[![CI](https://github.com/GeriHB/secdoclint/actions/workflows/ci.yml/badge.svg)](https://github.com/GeriHB/secdoclint/actions/workflows/ci.yml)

`SecDocLint` is a publication-safety and consistency linter for cybersecurity Markdown repositories.

It helps catch problems that ordinary Markdown linters do not understand, including exposed credentials, lab flags, authentication headers, oversized terminal dumps, generic screenshot descriptions, broken relative links, missing scope files, and contradictory validation language.

The tool is designed for:

- Penetration-test reports
- Security research notes
- CTF and lab write-ups
- Incident-response documentation
- Public GitHub portfolios
- Evidence-heavy Markdown repositories

## Why this exists

Security documentation often contains material that is technically valid but unsafe or unhelpful to publish:

- A full NTLM hash copied from `secretsdump`
- A Kerberos ticket or JWT left in a code block
- An `Authorization` header in captured HTTP
- A platform flag or recovered lab password
- A screenshot referenced as `![alt text]`
- A README that links to a file that no longer exists
- A section that says an attack was validated and later says it was never tested
- Hundreds of lines of raw terminal output where a short excerpt would be clearer

`SecDocLint` checks for these problems before the repository is shared

## Quick start

```bash
python -m pip install -e .
secdoclint check .
```

JSON output:

```bash
secdoclint check . --format json
```

Show only medium-and-higher findings:

```bash
secdoclint check . --min-severity medium
```

Use a custom configuration file:

```bash
secdoclint check . --config .secdoclint.toml
```

### Example output

```text
HIGH DOC-SECRET-003 docs/domain-compromise.md:88
  Authorization header may expose reusable authentication material.

MEDIUM DOC-MARKDOWN-002 docs/recon.md:41
  Generic image alt text does not explain what the evidence proves.

MEDIUM DOC-CONSISTENCY-001 docs/adcs.md:12
  The section contains both confirmed-validation language and a statement
  that the technique was not independently tested.
```

## Rules included in the MVP

### Publication safety

- Private-key headers
- Bearer and Basic authorization headers
- JWT-like tokens
- GitHub token formats
- Lab and CTF flags
- Full 32-byte hexadecimal credential material
- Kerberos-ticket-like Base64 blobs
- Sensitive tracked file types such as `.kirbi`, `.ccache`, `.ovpn`, `.pfx`, `.pcap`, and dumps

### Documentation quality

- Broken relative Markdown links
- Generic image alt text
- Oversized fenced code blocks
- Missing repository scope or disclaimer files
- Contradictory validation language inside one section

## Configuration

Create `.secdoclint.toml` in the repository root:

```toml
exclude_globs = [
  ".git/**",
  ".venv/**",
  "vendor/**",
]

max_code_block_lines = 80
required_any = [
  ["DISCLAIMER.md"],
  ["docs/00-scope-and-methodology.md", "docs/00-lab-environment-and-scope.md"],
]

[rule_overrides]
"FILE-SENSITIVE-001" = "high"
"DOC-CODE-001" = "low"
```

## Exit codes

- `0`: no findings at or above the selected severity
- `1`: findings were detected
- `2`: invalid arguments or scan failure

## Project scope

This first version intentionally focuses on Markdown-first repositories. It does not attempt to replace secret scanners, SAST platforms, or professional reporting systems.

Its purpose is to make security documentation safer, more consistent, and easier to review before publication.

## Development

Run the tests:

```bash
python -m unittest discover -s tests -v
```

## Licence

MIT
