"""Insecure client-side detection (OWASP A05:2021).

Browser code fails in a different way from server code: a single sink turns
attacker-controlled data into script execution in the user's session. Each check
here flags a *sensitive construct* only when the guard that would make it safe
is absent, so the fix hint stays actionable.

Scope is deliberately the pattern surface, like every other rule module: plain
stdlib ``re`` over lines, no parser, no cross-file or dataflow analysis. Every
pattern below is linear (no nested quantifier), so there is no backtracking
blow-up to cap.
"""

import logging
import re
from pathlib import Path

from ..models import Finding, Severity

logger = logging.getLogger(__name__)

RULE_ID = "VGB-030"

# Line prefixes that carry no executable meaning.
COMMENT_PREFIXES = ("#", "//", "*", "<!--", "/*")

# How far past a sink the guard may sit and still be the same construct — a
# multi-line ``<a>`` tag or a message callback both put ``rel="noopener"`` and
# ``event.origin`` on a following line.
# ponytail: fixed line window; a real parser if constructs ever nest deeper.
GUARD_LOOKAHEAD_LINES = 3

# A whole string literal, quotes included, and nothing else. A template
# literal, a concatenation or a bare variable fails this: all three are sinks.
LITERAL_RE = re.compile(r"""^(['"])[^'"]*\1\)?\s*;?\s*$""")

# Markup sinks. ``=(?!=)`` keeps ``innerHTML === '<b>ok</b>'`` out: a comparison
# executes nothing. ``insertAdjacentHTML`` is a call, so its value is the
# argument after the position literal.
HTML_SINK_RE = re.compile(
    r"""(?<![\w])(?P<obj>[\w.$]*)\.(?P<sink>innerHTML|outerHTML|insertAdjacentHTML)\s*(?P<op>\+?=(?!=)|\()"""
)

# document.write/writeln inject markup into the page being parsed.
DOCUMENT_WRITE_RE = re.compile(r"""(?<![\w])document\s*\.\s*write(?:ln)?\s*\(""")

# Receiving side: a message handler that trusts any sender.
MESSAGE_LISTENER_RE = re.compile(r"""(?<![\w])addEventListener\s*\(\s*['"]message['"]""")

# An origin comparison, the only thing that makes a message handler safe.
ORIGIN_GUARD_RE = re.compile(r"""\.origin\s*[!=]==?""")

# Sending side: '*' hands the payload to any frame that listens.
POST_MESSAGE_RE = re.compile(r"""(?<![\w])postMessage\s*\(""")
WILDCARD_TARGET_RE = re.compile(r"""['"]\*['"]""")

# Web storage writes. ``setItem`` is a call, a bare assignment is not, and
# ``getItem`` matches neither.
STORAGE_WRITE_RE = re.compile(
    r"""(?<![\w.])(?P<store>localStorage|sessionStorage)\s*(?:\.\s*setItem\s*\(|\.\s*(?P<member>[\w$]+)\s*=(?!=))"""
)

# A storage key or a quoted value that names a credential. Matched against the
# static text on the line — the storage member name and the string literals —
# never a variable, which is where the value is not visible to the scanner.
SECRET_LITERAL_RE = re.compile(
    r"""(?i)(?:api[_-]?key|apikey|auth[_-]?token|access[_-]?token|client[_-]?secret|"""
    r"""private[_-]?key|session[_-]?secret|token|secret|password|passwd|pwd|jwt|bearer)"""
)
QUOTED_RE = re.compile(r"""(['"])(?:(?!\1).)*\1""")

# Reverse tabnabbing: a new browsing context that keeps a handle on the opener.
TARGET_BLANK_RE = re.compile(r"""target\s*=\s*['"]_blank['"]""", re.IGNORECASE)
NOOPENER_RE = re.compile(r"""rel\s*=\s*['"][^'"]*(?:noopener|noreferrer)""", re.IGNORECASE)


def _snippet(line: str) -> str:
    text = line.strip()
    return text if len(text) <= 120 else text[:120] + "..."


def _static_value(line: str, match: re.Match, drop_position: bool = False) -> bool:
    """True when the value reaching *match* is a plain string literal."""
    rest = line[match.end() :]
    if drop_position:
        # insertAdjacentHTML(position, value): drop the position literal. Not
        # for document.write, whose single argument may contain commas.
        rest = rest.split(",", 1)[-1]
    return bool(LITERAL_RE.match(rest.strip().lstrip("(").strip()))


def _matches(lines: list[str], index: int, line: str):
    """Yield ``(rule_id, severity, column, message, fix_hint)`` for one line.

    ``index`` is the zero-based line number, used only to read the guard
    lookahead; the reported location is always the real line the sink is on.
    """
    window = lines[index : index + 1 + GUARD_LOOKAHEAD_LINES]
    text = "\n".join(window)

    for match in HTML_SINK_RE.finditer(line):
        sink = match.group("sink")
        if not _static_value(line, match, drop_position=match.group("op") == "("):
            yield (
                RULE_ID,
                Severity.HIGH,
                match.start() + 1,
                f"DOM XSS sink: {sink} assigned a non-literal value",
                "Assign to textContent instead, or escape the value before it reaches the DOM",
            )

    for match in DOCUMENT_WRITE_RE.finditer(line):
        if not _static_value(line, match):
            yield (
                RULE_ID,
                Severity.HIGH,
                match.start() + 1,
                "document.write() renders a non-literal value into the page",
                "Build the markup with DOM APIs (createElement/textContent) instead of document.write",
            )

    for match in MESSAGE_LISTENER_RE.finditer(line):
        if not ORIGIN_GUARD_RE.search(text):
            yield (
                RULE_ID,
                Severity.HIGH,
                match.start() + 1,
                "postMessage() handler with no event.origin check",
                "Reject the event unless event.origin matches the expected origin",
            )

    for match in POST_MESSAGE_RE.finditer(line):
        if WILDCARD_TARGET_RE.search(line):
            yield (
                RULE_ID,
                Severity.MEDIUM,
                match.start() + 1,
                "postMessage() sent to a wildcard target origin",
                "Pass the exact target origin instead of '*'",
            )

    for match in STORAGE_WRITE_RE.finditer(line):
        literals = [m.group(0) for m in QUOTED_RE.finditer(line)]
        keys = [match.group("member") or "", *literals]
        if any(SECRET_LITERAL_RE.search(key) for key in keys):
            store = match.group("store")
            yield (
                RULE_ID,
                Severity.HIGH,
                match.start() + 1,
                f"Credential-looking value written to {store}",
                "Keep tokens and keys out of web storage; use an httpOnly cookie or a short-lived token",
            )

    for match in TARGET_BLANK_RE.finditer(line):
        if not NOOPENER_RE.search(text):
            yield (
                RULE_ID,
                Severity.MEDIUM,
                match.start() + 1,
                'target="_blank" without rel="noopener"',
                'Add rel="noopener noreferrer" so the opened page cannot reach window.opener',
            )


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for insecure client-side patterns (OWASP A05:2021)."""
    findings: list[Finding] = []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    lines = content.splitlines()
    # One finding per sink location: a line that trips the same check twice
    # (two markup sinks, a duplicated pattern) must not double-report.
    seen: set[tuple[str, int]] = set()

    for line_num, line in enumerate(lines, 1):
        if line.strip().startswith(COMMENT_PREFIXES):
            continue

        try:
            matched = list(_matches(lines, line_num - 1, line))
        except Exception:
            # An unexpected line shape must not abort the file, let alone the
            # scan: log it and move on to the next line.
            logger.debug("client-side rule failed on %s line %s", path, line_num, exc_info=True)
            continue

        for rule_id, severity, column, message, fix_hint in matched:
            key = (rule_id, line_num)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    file=str(path),
                    line=line_num,
                    column=column,
                    snippet=_snippet(line),
                    fix_hint=fix_hint,
                )
            )

    return findings
