"""Insecure Design detection (OWASP A04:2021).

Insecure Design is a category of flaws where a control is missing by design,
not a bug in an otherwise sound control. Each rule here flags a *sensitive
construct* only when the guard that would make it safe is absent from the
same handler, so the fix hint stays actionable.

Scope is deliberately the pattern surface, like every other rule module: plain
stdlib ``re`` over lines, no cross-file or dataflow analysis.
"""

import re
from pathlib import Path

from ..models import Finding, Severity
from .missing_auth import _endpoint_unit

# Authorization checks that make a sensitive handler acceptable (VGB-020).
AUTH_GUARD_PATTERNS = [
    r"""(?i)(?:login_required|auth_required|require_auth|check_permission|has_permission)""",
    r"""(?i)(?:authorize|authorized|permission_required|roles_required)""",
    r"""(?i)Depends\s*\(\s*(?:get_current_user|verify_token|require_admin)""",
    r"""(?i)(?:is_admin|is_staff|require_perms)""",
]

# Rate limiting that makes an API route acceptable (VGB-021).
RATE_LIMIT_GUARD_PATTERNS = [
    r"""(?i)@?(?:rate_limit|ratelimit|limiter\.limit|throttle|slowapi|flask_limiter)""",
]

# Validation that makes a user-input flow acceptable (VGB-022).
VALIDATION_GUARD_PATTERNS = [
    r"""(?i)\b(?:validate|sanitize|escape|clean|coerce|check)\w*\s*\(""",
]

# State/precondition checks that make a transition acceptable (VGB-024).
STATE_GUARD_PATTERNS = [
    r"""(?i)\b(?:if|assert|elif)\b[^\n]*\.\s*(?:status|state|can_|allowed_)""",
    r"""(?i)\bif\s+not\b[^\n]*\.\w+""",
]

# Security headers that make a response acceptable (VGB-025).
HEADER_GUARD_PATTERNS = [
    r"""(?i)Content-Security-Policy""",
    r"""(?i)(?:X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security)""",
    r"""(?i)(?:Referrer-Policy|Permissions-Policy|helmet)\b""",
]

# Handlers whose *name* promises a sensitive operation.
SENSITIVE_HANDLER_RE = re.compile(
    r"""(?i)^\s*(?:async\s+def|def|function)\s+\w*(?:delete|remove|drop|purge|admin|privileged|transfer|refund|withdraw)\w*\s*\("""
)

# Routes under an /api prefix — the surface abuse is aimed at.
API_ROUTE_RE = re.compile(
    r"""(?i)@\w+\.(?:get|post|put|delete|patch|route)\s*\(\s*['"][^'"]*/api/"""
)

# Handlers that move an object between states.
STATE_TRANSITION_RE = re.compile(
    r"""(?i)^\s*(?:async\s+def|def|function)\s+\w*(?:approve|reject|cancel|confirm|transition|complete|activate|deactivate|close)\w*\s*\("""
)

# Response construction — the place security headers must be set.
RESPONSE_BUILD_RE = re.compile(
    r"""(?i)\b(?:Response|make_response|JsonResponse|new\s+Response|res\.send|render_template)\s*(?:\(|\.)"""
)

# Where untrusted data enters.
USER_INPUT_RE = re.compile(
    r"""(?i)\b(?:request\.(?:args|form|json|data|query|params|body|GET|POST)|input\s*\(|sys\.argv|os\.environ|getenv\s*\()"""
)

# What makes that data dangerous once it arrives.
SENSITIVE_SINK_RE = re.compile(
    r"""(?i)\b(?:exec|eval|executescript|os\.system|subprocess\.\w+|cursor\.execute|\.raw\s*\(|select\s+.+\s+from|delete\s+from|drop\s+table)"""
)

# Hardcoded insecure defaults, checked line by line (VGB-023).
INSECURE_DEFAULT_PATTERNS = [
    (
        re.compile(r"""(?i)\b(?:ssl_verify|verify_ssl|verify|reject_unauthorized)\s*[=:]\s*False"""),
        "TLS verification disabled by default — connections can be intercepted",
        "Keep certificate verification enabled and configure a CA bundle instead",
    ),
    (
        re.compile(r"""(?i)\w*(?:secure|httponly|secure_cookie)\w*\s*[=:]\s*False"""),
        "Cookie security flag disabled by default — session cookie travels in cleartext",
        "Set the secure/HttpOnly cookie flags to True",
    ),
    (
        re.compile(r"""(?i)\b(?:host|bind|listen)\s*[=:]\s*['"]0\.0\.0\.0['"]"""),
        "Service bound to 0.0.0.0 — exposed on every interface by default",
        "Bind to a specific interface or front the service with a reverse proxy",
    ),
]

# How far past the input source a sink may sit and still be the same flow.
# ponytail: fixed line window; a real dataflow pass if flows ever span functions.
SINK_LOOKAHEAD_LINES = 3

# (rule_id, severity, trigger, guards, message, fix_hint) for the rules whose
# trigger line opens a handler and whose guards are looked up inside it.
UNIT_RULES = [
    (
        "VGB-020",
        Severity.HIGH,
        SENSITIVE_HANDLER_RE,
        AUTH_GUARD_PATTERNS,
        "Sensitive handler without an authorization check",
        "Require an authenticated, permission-checked subject before the operation",
    ),
    (
        "VGB-021",
        Severity.MEDIUM,
        API_ROUTE_RE,
        RATE_LIMIT_GUARD_PATTERNS,
        "API route without rate limiting",
        "Apply a rate limit to the route (e.g., @limiter.limit) so abuse is throttled",
    ),
    (
        "VGB-024",
        Severity.HIGH,
        STATE_TRANSITION_RE,
        STATE_GUARD_PATTERNS,
        "State transition without a precondition check",
        "Verify the current state before transitioning, so the operation cannot be replayed",
    ),
    (
        "VGB-025",
        Severity.MEDIUM,
        RESPONSE_BUILD_RE,
        HEADER_GUARD_PATTERNS,
        "Response built without security headers",
        "Set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options and HSTS",
    ),
]


def _snippet(line: str) -> str:
    text = line.strip()
    return text if len(text) <= 120 else text[:120] + "..."


def _guarded(lines: list[str], guards: list[str]) -> bool:
    return any(re.search(pattern, line) for line in lines for pattern in guards)


def _unvalidated_input(lines: list[str], index: int) -> re.Match | None:
    """Return the user-input match when raw input reaches a sink unvalidated."""
    match = USER_INPUT_RE.search(lines[index])
    if not match:
        return None

    window = lines[index : index + 1 + SINK_LOOKAHEAD_LINES]
    text = "\n".join(window)
    if any(re.search(pattern, text) for pattern in VALIDATION_GUARD_PATTERNS):
        return None
    return match if SENSITIVE_SINK_RE.search(text) else None


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for insecure design patterns (OWASP A04:2021)."""
    findings: list[Finding] = []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(("#", "//")):
            continue

        for pattern, message, fix_hint in INSECURE_DEFAULT_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append(
                    Finding(
                        rule_id="VGB-023",
                        severity=Severity.HIGH,
                        message=message,
                        file=str(path),
                        line=line_num,
                        column=match.start() + 1,
                        snippet=_snippet(line),
                        fix_hint=fix_hint,
                    )
                )

        for rule_id, severity, pattern, guards, message, fix_hint in UNIT_RULES:
            match = pattern.search(line)
            if match and not _guarded(_endpoint_unit(lines, line_num - 1), guards):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        file=str(path),
                        line=line_num,
                        column=match.start() + 1,
                        snippet=_snippet(line),
                        fix_hint=fix_hint,
                    )
                )

        flow = _unvalidated_input(lines, line_num - 1)
        if flow:
            findings.append(
                Finding(
                    rule_id="VGB-022",
                    severity=Severity.CRITICAL,
                    message="Unvalidated user input reaches a sensitive operation",
                    file=str(path),
                    line=line_num,
                    column=flow.start() + 1,
                    snippet=_snippet(line),
                    fix_hint="Validate and coerce the input at the trust boundary before using it",
                )
            )

    return findings