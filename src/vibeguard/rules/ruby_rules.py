"""Ruby security pattern detection.

Ruby's dynamic surface is the classic set of code-execution sinks: ``system``
with a shell string built by concatenation or interpolation is command
injection, ``eval`` on a non-literal value is arbitrary code execution, and
``constantize`` resolving a constant from user-sourced input is an
object-resolution hole. The patterns are gated to ``.rb``/``.erb`` files so
they do not fire in other languages that share the method names.
"""

import re
from pathlib import Path

from ..models import Finding, Severity

MAX_LINE_LENGTH = 50_000  # 50 KB

RUBY_EXTENSIONS = {".rb", ".erb"}

# A word that marks a value as user-sourced on a line.
_USER_TOKEN = r"\b(?:params|user|input|request|req|args|body)\w*"

# Pre-compiled Ruby patterns: (compiled regex, message, severity, fix_hint).
RUBY_PATTERNS = [
    (
        re.compile(r"system\s*\([^)]*(?:#\{|\"\s*\+)"),
        "system() with a concatenated / interpolated command — command injection risk",
        Severity.CRITICAL,
        "Pass a fixed command array to system; never build a shell string with user input.",
    ),
    (
        re.compile(r"eval\s*\(\s*[A-Za-z_]\w*"),
        "eval() over a non-literal value — arbitrary code execution vulnerability",
        Severity.CRITICAL,
        "Do not eval user-controlled strings; use an allowlist of operations or a safe expression parser.",
    ),
    (
        re.compile(rf"{_USER_TOKEN}[^;]*?\.constantize"),
        "constantize() resolving a constant from user input — arbitrary object resolution",
        Severity.HIGH,
        "Map user input to an explicit allowlist of classes instead of calling constantize on it.",
    ),
]


def scan_file(path: Path) -> list[Finding]:
    """Scan a single Ruby file for the patterns above. Non-Ruby files are ignored."""
    findings: list[Finding] = []

    if path.suffix not in RUBY_EXTENSIONS:
        return findings

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]

        for compiled, message, severity, fix_hint in RUBY_PATTERNS:
            match = compiled.search(line)
            if match:
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                findings.append(
                    Finding(
                        rule_id="VGB-090",
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
