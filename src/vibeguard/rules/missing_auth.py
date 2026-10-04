"""Missing authentication detection."""

import re
from pathlib import Path

from ..models import Finding, Severity

# Patterns that suggest an endpoint exists
ENDPOINT_PATTERNS = [
    # Python Flask/FastAPI
    r"""(?i)@(?:app|router|blueprint)\.(?:get|post|put|delete|patch)\s*\(['"]([^'"]+)['"]""",
    # Python Flask with methods
    r"""(?i)@(?:app|router)\.route\s*\(['"]([^'"]+)['"].*methods\s*=\s*\[.*(?:POST|PUT|DELETE).*\]""",
    # Express.js
    r"""(?i)(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""",
    # Go net/http
    r"""(?i)http\.(?:HandleFunc|Handle)\s*\(\s*['"]([^'"]+)['"]""",
    # FastAPI decorators
    r"""(?i)@(?:app|router)\.(?:get|post|put|delete|patch)\s*\(""",
]

# Patterns that suggest authentication is present
AUTH_PATTERNS = [
    r"""(?i)(?:login_required|auth_required|require_auth|authenticate|jwt_required)""",
    r"""(?i)(?:Depends\s*\(\s*(?:get_current_user|verify_token|oauth2_scheme))""",
    r"""(?i)(?:middleware.*auth|auth.*middleware)""",
    r"""(?i)(?:passport|jwt|bearer|token.*verify)""",
]

# Endpoints that typically don't need auth
PUBLIC_ENDPOINTS = [
    r"""(?i)(?:/health|/ping|/status|/docs|/openapi|/static|/login|/register|/signup|/auth/callback)""",
]


# How many lines below a route decorator still count as "that endpoint".
# ponytail: fixed window; a real AST walk if routes ever need more context.
UNIT_LINES = 15

_DEF_START = re.compile(r"^\s*(?:async\s+def|def|function)\b")


def _endpoint_unit(lines: list[str], index: int) -> list[str]:
    """Return the lines belonging to the endpoint declared at *index*.

    That is the decorator stack around the route plus the definition line, where
    auth actually shows up (``@login_required``, ``Depends(get_current_user)``,
    ``requireAuth`` on an Express route...). Only this unit may suppress a
    finding: auth elsewhere in the file guards nothing.
    """
    start = index
    while start > 0 and lines[start - 1].lstrip().startswith("@"):
        start -= 1

    end = min(len(lines), index + UNIT_LINES)
    for pos in range(index + 1, end):
        if _DEF_START.match(lines[pos]):
            return lines[start : pos + 1]
    return lines[start:end]


def _has_auth(lines: list[str]) -> bool:
    return any(re.search(pattern, line) for line in lines for pattern in AUTH_PATTERNS)


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for potentially unauthenticated endpoints."""
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
        
        for pattern in ENDPOINT_PATTERNS:
            match = re.search(pattern, line)
            if match:
                # Check if this is a public endpoint
                is_public = False
                for pub_pattern in PUBLIC_ENDPOINTS:
                    if re.search(pub_pattern, line):
                        is_public = True
                        break
                
                if not is_public and not _has_auth(_endpoint_unit(lines, line_num - 1)):
                    snippet = line.strip()
                    if len(snippet) > 120:
                        snippet = snippet[:120] + "..."
                    
                    findings.append(
                        Finding(
                            rule_id="VGB-006",
                            severity=Severity.HIGH,
                            message="Endpoint without visible authentication — ensure it is protected",
                            file=str(path),
                            line=line_num,
                            column=match.start() + 1,
                            snippet=snippet,
                            fix_hint=(
                                "Add authentication middleware or decorator "
                                "(e.g., @login_required, Depends(get_current_user))"
                            ),
                        )
                    )
    
    return findings
