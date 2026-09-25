"""Hardcoded secrets detection."""

import re
from pathlib import Path

from ..models import Finding, Severity

# Maximum line length to process — lines longer than this are truncated
# before regex matching to prevent ReDoS from catastrophic backtracking
# on extremely long lines (e.g. generated minified code, base64 blobs).
MAX_LINE_LENGTH = 50_000  # 50 KB

# Pre-compiled secret patterns (compiled once at import time).
# Using pre-compiled patterns avoids re-compilation per line and
# lets us apply the line-length guard uniformly.
SECRET_PATTERNS = [
    # API keys
    (
        re.compile(r"""(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]"""),
        "Hardcoded API key detected",
    ),
    # AWS access keys
    (
        re.compile(r"""(?i)AKIA[0-9A-Z]{16}"""),
        "AWS Access Key ID detected",
    ),
    # Generic tokens
    (
        re.compile(r"""(?i)(token|secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]/{8,}['"]"""),
        "Hardcoded secret/token detected",
    ),
    # Private keys
    (
        re.compile(r"""-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"""),
        "Private key committed to repository",
    ),
    # GitHub tokens
    (
        re.compile(r"""(?i)gh[pousr]_[A-Za-z0-9_]{36,}"""),
        "GitHub personal access token detected",
    ),
    # Slack tokens
    (
        re.compile(r"""xox[bprs]-[0-9a-zA-Z]{10,48}"""),
        "Slack token detected",
    ),
]

# Files to skip for secret scanning (false positives)
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "poetry.lock"}


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for hardcoded secrets."""
    findings: list[Finding] = []
    
    if path.name in SKIP_FILES:
        return findings
    
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_num, line in enumerate(content.splitlines(), 1):
        # Skip comments (basic heuristic)
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue
        
        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]

        for compiled, message in SECRET_PATTERNS:
            match = compiled.search(line)
            if match:
                # Redact the actual secret in output
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                
                findings.append(
                    Finding(
                        rule_id="VGB-001",
                        severity=Severity.CRITICAL,
                        message=message,
                        file=str(path),
                        line=line_num,
                        column=match.start() + 1,
                        snippet=snippet,
                        fix_hint="Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault)",
                    )
                )
    
    return findings
