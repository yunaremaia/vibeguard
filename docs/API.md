# VibeGuard API

Public surface for embedding VibeGuard in scripts and CI.

## Package

```python
from vibeguard import __version__
from vibeguard.scanner import scan_directory, scan_file, should_scan
from vibeguard.formatters import format_text, format_json, format_sarif
```

| Symbol | Module | Role |
|--------|--------|------|
| `__version__` | `vibeguard` | Package version string |
| `scan_directory(path)` | `scanner` | Scan a tree |
| `scan_file(path)` | `scanner` | Run all rules on one file |
| `should_scan(path)` | `scanner` | Extension + skip-pattern gate |
| `format_text` / `format_json` / `format_sarif` | `formatters` | Output helpers |

## CLI

```bash
vibeguard [target] [-f text|json|sarif] [-o file] [--min-severity LOW|MEDIUM|HIGH|CRITICAL]
vibeguard --version
```

Default target is `.`.

## Rules

Registered in `scanner.RULES`: secrets, SQL injection, dangerous functions, CORS/debug, missing auth.
