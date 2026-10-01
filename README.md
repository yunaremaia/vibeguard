
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
pip install vibeguard-py
```

> **Note on the package name:** the short `vibeguard` name on PyPI belongs to a
> different, unrelated project by a different author. This distribution is
> `vibeguard-py` — a static scanner for AI-generated code. The CLI command is
> still `vibeguard`, and the importable module is still `vibeguard`.

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
      - run: pip install vibeguard-py
      - run: vibeguard . --format sarif --output vibeguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vibeguard.sarif
```


If this tool is useful to you, a star helps other people find it.

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
