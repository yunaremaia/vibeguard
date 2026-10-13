"""Rust security pattern detection.

Rust's safety story makes the idioms below genuinely dangerous: an ``unsafe``
block is where unsoundness enters the program, ``std::process::Command``
built from a formatted argument is command injection, and an ``unwrap()`` /
``expect()`` on a user-sourced value is a panic reachable from the outside.
The patterns are gated to ``.rs`` files so they never fire in other languages
that happen to use the same words.
"""

import re
from pathlib import Path

from ..models import Finding, Severity

MAX_LINE_LENGTH = 50_000  # 50 KB

RUST_EXTENSIONS = {".rs"}

# A word that marks a value as user-sourced on a line; ``\w*`` lets it absorb
# ``_value`` / ``_input`` suffixes so ``user_value`` counts.
_USER_TOKEN = r"\b(?:user|input|request|args|param|body|stdin|env|payload|form)\w*"

# Pre-compiled Rust patterns: (compiled regex, message, severity, fix_hint).
RUST_PATTERNS = [
    (
        re.compile(r"\bunsafe\s*\{"),
        "unsafe block — unsoundness can enter the program here",
        Severity.MEDIUM,
        "Keep unsafe blocks minimal and document the safety invariant they rely on; use a safe API where one exists.",
    ),
    (
        re.compile(
            r"std::process::Command[^;]*\.arg\([^)]*(?:format!|\.to_string\(\)|&\s*(?:user|input|req|args|body))"
        ),
        "std::process::Command argument built from formatted/user input — command injection risk",
        Severity.CRITICAL,
        "Pass a fixed argv to Command; never build an argument with format! or from user input.",
    ),
    (
        re.compile(
            rf"{_USER_TOKEN}.*\b(?:unwrap|expect)\s*\(|\b(?:unwrap|expect)\s*\([^)]*{_USER_TOKEN}"
        ),
        "unwrap()/expect() on a user-sourced value — a bad value panics the thread",
        Severity.HIGH,
        "Propagate the Result instead of calling unwrap()/expect() on externally-sourced data.",
    ),
]


def scan_file(path: Path) -> list[Finding]:
    """Scan a single Rust file for the patterns above. Non-Rust files are ignored."""
    findings: list[Finding] = []

    if path.suffix not in RUST_EXTENSIONS:
        return findings

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue

        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]

        for compiled, message, severity, fix_hint in RUST_PATTERNS:
            match = compiled.search(line)
            if match:
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                findings.append(
                    Finding(
                        rule_id="VGB-070",
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
