"""High-entropy hardcoded credential detection (VGB-040).

VGB-001 flags a secret *shape*: any quoted literal assigned to a name that
mentions ``api_key`` or ``token``, whatever it contains. That is cheap and it
over-reports — ``password = "changeme"`` is not a leaked credential. VGB-040
answers the different question "is this literal random-looking?", by scoring
Shannon entropy over the value.

Scope is the same pattern surface as every other rule module: ``re`` over
lines, stdlib only, no parser. This is *not* a replacement for a secret
scanner: a leaked passphrase can be low-entropy and escape, and a base64 test
fixture assigned to ``api_key`` will be reported. The entropy threshold and the
placeholder allowlist are the knobs.
"""

import math
import re
from pathlib import Path

from ..models import Finding, Severity

RULE_ID = "VGB-040"

MAX_LINE_LENGTH = 50_000  # 50 KB
MIN_VALUE_LENGTH = 16
# Bits per character. 3.5 sits above dictionary words and below random
# alphanumerics. It is *not* enough on its own: Shannon entropy on a 30-char
# string is biased high (the ceiling is log2(30) ~ 4.9), so English prose
# scores 4.16 and outranks random hex. MIN_CHAR_CLASSES is what actually
# separates the two — prose is one character class, a credential is several.
# ponytail: fixed thresholds; a per-language charset model if FP rate matters.
MIN_ENTROPY = 3.5
MIN_CHAR_CLASSES = 2

# ``name = "value"`` / ``name: "value"`` where name mentions a credential.
# The value is captured whole so it can be scored.
CREDENTIAL_ASSIGNMENT_RE = re.compile(
    rf"""(?ix)
    \b (?P<name>
    (?: [a-z0-9]* [_.-] )*            # optional namespace prefix (db_, AWS_, ...)
    (?: secret | token | password | passwd | pwd
      | api[_.-]?key | apikey | auth | credential | private[_.-]?key
      | access[_.-]?key | signing[_.-]?key | client[_.-]?secret )
    [a-z0-9_]*
    )
    \b
    \s* [:=] \s*
    (?P<quote> ['"] )
    (?P<value> [^'"\n]{{{MIN_VALUE_LENGTH},}} )
    (?P=quote)
    """
)

# Values that name themselves as placeholders, and indirections that read a
# real secret at runtime rather than embedding one.
PLACEHOLDER_RE = re.compile(
    r"""(?ix)
    (?: changeme | change_me | your[_.-]? | my[_.-]?secret | placeholder
      | example | sample | dummy | fake | redacted | todo | fixme
      | insert[_.-]? | replace[_.-]? | x{4,} | \*{4,}
      | os\.environ | getenv | process\.env | \$ \{ | \$\( | \{\{ | <% )
    """
)


def shannon_entropy(value: str) -> float:
    """Shannon entropy of ``value`` in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def char_classes(value: str) -> int:
    """How many of {lowercase, uppercase, digit, other} the value draws from.

    Whitespace is not a class: it is what makes prose readable, and counting it
    would let ``"the quick brown fox jumps over"`` pass as mixed-case.
    """
    classes = 0
    if any(c.islower() for c in value):
        classes += 1
    if any(c.isupper() for c in value):
        classes += 1
    if any(c.isdigit() for c in value):
        classes += 1
    if any(not c.isalnum() and not c.isspace() for c in value):
        classes += 1
    return classes


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for high-entropy credentials."""
    findings: list[Finding] = []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*")):
            continue

        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]

        # At most one finding per line: a line can satisfy the assignment
        # regex twice (``api_key = key``, then a ``token = token`` alias), and
        # the same secret reported N times is noise, not signal.
        match = CREDENTIAL_ASSIGNMENT_RE.search(line)
        if not match:
            continue

        value = match.group("value")
        if PLACEHOLDER_RE.search(value):
            continue
        if char_classes(value) < MIN_CHAR_CLASSES:
            continue
        if shannon_entropy(value) < MIN_ENTROPY:
            continue

        snippet = line.strip()
        if len(snippet) > 120:
            snippet = snippet[:120] + "..."

        findings.append(
            Finding(
                rule_id=RULE_ID,
                severity=Severity.CRITICAL,
                message=(
                    f"High-entropy value assigned to '{match.group('name')}' "
                    f"({shannon_entropy(value):.2f} bits/char) — probable hardcoded credential"
                ),
                file=str(path),
                line=line_num,
                column=match.start() + 1,
                snippet=snippet,
                fix_hint=(
                    "Load the credential from the environment or a secrets manager "
                    "(AWS Secrets Manager, HashiCorp Vault) and rotate the exposed value"
                ),
            )
        )

    return findings
