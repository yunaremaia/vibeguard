"""Go security pattern detection.

Go has its own injection surface that the category-based rules do not cover:
command injection through ``exec.Command`` with a formatted argument, SSRF
through ``http.Get`` with a user-chosen URL, and SQL injection through
``database/sql`` calls whose arguments are built with ``fmt.Sprintf`` or
string concatenation. The pattern set is gated to ``.go`` files so it does not
fire on the same constructs in other languages.
"""

import re
from pathlib import Path

from ..models import Finding, Severity

MAX_LINE_LENGTH = 50_000  # 50 KB

GO_EXTENSIONS = {".go"}

# Pre-compiled Go patterns: (compiled regex, message, severity, fix_hint).
# The regexes only fire when the argument is *built* from something dynamic
# (``fmt.Sprintf`` or string concatenation), so a call on a plain quoted
# constant -- the safe idiom -- is left alone.
GO_PATTERNS = [
    (
        re.compile(r'exec\.Command[A-Za-z]*\([^)]*(?:fmt\.Sprintf|"\s*\+)'),
        "exec.Command argument built from user input — command injection risk",
        Severity.CRITICAL,
        "Pass a fixed argument list to exec.Command; never build it with fmt.Sprintf or by concatenating user input.",
    ),
    (
        re.compile(r'https?\.Get\s*\([^)]*(?:fmt\.Sprintf|"\s*\+)'),
        "http.Get with a formatted or concatenated URL — SSRF risk",
        Severity.HIGH,
        "Validate and allowlist outbound URLs; do not let user input choose the target host.",
    ),
    (
        re.compile(r'sql\.Open\s*\([^)]*(?:fmt\.Sprintf|"\s*\+)'),
        "sql.Open with a user-controlled DSN — injection / data-exfiltration risk",
        Severity.HIGH,
        "Keep the data-source name fixed; do not splice user input into the connection string.",
    ),
    (
        re.compile(r'\b(?:db|stmt)\.(?:Exec|Query|QueryRow)\s*\([^)]*(?:fmt\.Sprintf|"\s*\+)'),
        "database/sql query built with fmt.Sprintf or concatenation — SQL injection risk",
        Severity.CRITICAL,
        "Use a parameterised query (db.Query('... $1 ...', args)) instead of formatting user input into the SQL string.",
    ),
]


def scan_file(path: Path) -> list[Finding]:
    """Scan a single Go file for the patterns above. Non-Go files are ignored."""
    findings: list[Finding] = []

    if path.suffix not in GO_EXTENSIONS:
        return findings

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(("#", "//")):
            continue

        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]

        for compiled, message, severity, fix_hint in GO_PATTERNS:
            match = compiled.search(line)
            if match:
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                findings.append(
                    Finding(
                        rule_id="VGB-060",
                        severity=severity,
                        message=message,
                        file=str(path),
                        line=line_num,
                        column=match.start() + 1,
                        snippet=snippet,
                        fix_hint=fix_hint,
                    )
                )

    return findings
