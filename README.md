
# VibeGuard


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
pip install vibeguard
```

## Usage

```bash
# Scan current directory
vibeguard scan .

# Scan specific directory
vibeguard scan /path/to/project

# Output as JSON
vibeguard scan . --format json

# Output as SARIF (for GitHub Code Scanning)
vibeguard scan . --format sarif --output results.sarif

# Only show critical and high severity
vibeguard scan . --min-severity HIGH
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
      - run: pip install vibeguard
      - run: vibeguard scan . --format sarif --output vibeguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vibeguard.sarif
```

## License

MIT
