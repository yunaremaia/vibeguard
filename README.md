
# VibeGuard

![CI](https://github.com/yunaremaia/vibeguard/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![License](https://img.shields.io/github/license/yunaremaia/vibeguard)
![Stars](https://img.shields.io/github/stars/yunaremaia/vibeguard)



Security scanner for AI-generated code. Detects common security issues in "vibe-coded" applications.
[Changelog](CHANGELOG.md)

## Why VibeGuard?

AI coding assistants (Claude Code, Codex, Cursor) enable rapid development but often produce code with security gaps:

- Hardcoded secrets and API keys
- SQL injection via string formatting
- Dangerous use of `eval()` / `exec()` with user input
- CORS wildcard configurations
- Debug mode left enabled
- Missing authentication on endpoints

VibeGuard scans your codebase and flags these issues before they reach production.

## Install

```bash
pip install git+https://github.com/yunaremaia/vibeguard.git
```

> **Note on installation:** this project is not published on PyPI, so it installs
> from the git repository rather than from the index.

> **Note on the package name:** the short `vibeguard` name on PyPI belongs to a
> different, unrelated project by a different author. The distribution declared
> in `pyproject.toml` is `vibeguard-py` — a static scanner for AI-generated
> code. The CLI command is still `vibeguard`, and the importable module is still
> `vibeguard`.

## Usage

```bash
# Scan current directory
vibeguard .

# Scan specific directory
vibeguard /path/to/project

# Scan a single file
vibeguard app.py

# Output as JSON
vibeguard . --format json

# Output as SARIF (for GitHub Code Scanning)
vibeguard . --format sarif --output results.sarif

# Only show critical and high severity
vibeguard . --min-severity HIGH
```

## Detections

| Rule ID | Severity | Description |
|---------|----------|-------------|
| VGB-001 | CRITICAL | Hardcoded secrets (API keys, tokens, passwords) |
| VGB-002 | CRITICAL | SQL injection via string formatting |
| VGB-003 | CRITICAL | Dangerous functions (eval, exec, os.system) with user input |
| VGB-004 | HIGH | CORS wildcard origin |
| VGB-005 | MEDIUM | Debug mode enabled |
| VGB-006 | HIGH | Endpoints without visible authentication |
| VGB-020 | HIGH | Sensitive handlers (delete, admin, transfer) without an authorization check |
| VGB-021 | MEDIUM | API routes without rate limiting |
| VGB-022 | CRITICAL | Unvalidated user input reaching exec/SQL/shell operations |
| VGB-023 | HIGH | Insecure defaults (TLS verify off, cookie flags off, bound to 0.0.0.0) |
| VGB-024 | HIGH | State transitions without a precondition check |
| VGB-025 | MEDIUM | Responses built without security headers (CSP, HSTS, X-Frame-Options) |

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  vibeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install git+https://github.com/yunaremaia/vibeguard.git
      - run: vibeguard . --format sarif --output vibeguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vibeguard.sarif
```


If this tool is useful to you, a star helps other people find it.

## Sponsoring / Treasury

VibeGuard is MIT licensed and maintained in the open. Scanning AI-generated code for the
security issues it tends to ship with stays free, and keeping the detection rules
current as new vulnerability patterns show up is the ongoing work. If it saves you
time, you can support continued development through GitHub Sponsors or the Solana
treasury below.

Funding details are declared in [`.github/FUNDING.yml`](.github/FUNDING.yml), which is
what GitHub reads to render the **Sponsor** button on this repository.

- **GitHub Sponsors:** [@yunaremaia](https://github.com/sponsors/yunaremaia)
- **Solana:** `Eeztv1nCYUt1fwGWpzKC948gaWfjejYCAuLtUMgzDWbW`

Use the Solana address only for intended donations. Anyone can generate a similar
address, so verify the address against `.github/FUNDING.yml` before sending funds.

## Related tools

- **[agent-guard](https://github.com/yunaremaia/agent-guard)** — enforce guardrails on AI agent tool calls
- **[ci-test-gate](https://github.com/yunaremaia/ci-test-gate)** — block PRs until the required tests actually run
- **[sandbox-ffi-layers](https://github.com/yunaremaia/sandbox-ffi-layers)** — layer FFI calls behind a sandbox boundary
- **[driftcheck](https://github.com/yunaremaia/driftcheck)** — detect version drift between docs and toolchain files

Part of a family of focused, single-purpose developer tools — each one does one thing
and does it well.

## License

MIT

## Exit codes

| Code | Meaning |
|------|--------|
| `0` | Clean / no actionable findings |
| `1` | Findings reported (use in CI gates) |
| `2` | Invalid arguments or unreadable input |

## API

See [docs/API.md](docs/API.md) for the Python API and CLI flags.
