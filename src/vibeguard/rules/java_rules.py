"""Java security pattern detection.

Java's three classic holes: ``readObject()`` on attacker-chosen bytes is remote
code execution through deserialization, ``Runtime.exec()`` built from string
concatenation is command injection, and ``executeQuery()`` fed a string built by
concatenation (the tell of a raw ``Statement`` rather than a
``PreparedStatement``) is SQL injection. The patterns are gated to ``.java``
files so they do not fire in other languages that share the keywords.
"""

import re
from pathlib import Path

from ..models import Finding, Severity

MAX_LINE_LENGTH = 50_000  # 50 KB

JAVA_EXTENSIONS = {".java"}

# Pre-compiled Java patterns: (compiled regex, message, severity, fix_hint).
# Each only fires when the argument is *built* (concatenation / formatting), so
# the safe parameterised-idiom calls are left alone.
JAVA_PATTERNS = [
    (
        re.compile(r"\.readObject\s*\(|new\s+ObjectInputStream\s*\("),
        "Object deserialization — attacker bytes can run arbitrary code",
        Severity.CRITICAL,
        "Do not deserialize attacker-controlled bytes; if unavoidable, use an ObjectInputFilter allowlist of serializable classes.",
    ),
    (
        re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*[\"']\s*\+"),
        "Runtime.exec built from string concatenation — command injection risk",
        Severity.CRITICAL,
        "Pass a fixed command array to Runtime.exec / ProcessBuilder; never build it by concatenating user input.",
    ),
    (
        re.compile(r"\.executeQuery\s*\([^)]*[\"']\s*\+"),
        "executeQuery built from string concatenation — SQL injection risk",
        Severity.CRITICAL,
        "Use a PreparedStatement with bound parameters instead of concatenating user input into the SQL string.",
    ),
]


def scan_file(path: Path) -> list[Finding]:
    """Scan a single Java file for the patterns above. Non-Java files are ignored."""
    findings: list[Finding] = []

    if path.suffix not in JAVA_EXTENSIONS:
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

        for compiled, message, severity, fix_hint in JAVA_PATTERNS:
            match = compiled.search(line)
            if match:
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                findings.append(
                    Finding(
                        rule_id="VGB-080",
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
