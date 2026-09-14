"""CORS wildcard and debug mode detection."""

import re
from pathlib import Path

from ..models import Finding, Severity

CORS_PATTERNS = [
    # Python Flask/Django CORS wildcard
    (
        r"""(?i)CORS\s*\(.*origins\s*=\s*['"]\*['"]""",
        "CORS configured with wildcard origin (*) — allows any domain to make requests",
    ),
    # Manual CORS header wildcard
    (
        r"""(?i)(?:Access-Control-Allow-Origin|acao)\s*[:=]\s*['"]\*['"]""",
        "Access-Control-Allow-Origin set to wildcard (*)",
    ),
    # JavaScript/Express CORS wildcard
    (
        r"""(?i)cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]""",
        "CORS origin set to wildcard (*) — allows any domain",
    ),
    # Regex-based CORS (dangerous)
    (
        r"""(?i)cors\s*\(\s*\{[^}]*origin\s*:\s*/.*\*/""",
        "CORS origin uses regex — may be overly permissive",
    ),
]

DEBUG_PATTERNS = [
    # Python debug mode
    (
        r"""(?i)(?:DEBUG|debug)\s*=\s*True""",
        "Debug mode enabled — should be False in production",
    ),
    # Flask debug
    (
        r"""(?i)app\.run\s*\(.*debug\s*=\s*True""",
        "Flask app.run(debug=True) — debug mode in production exposes stack traces",
    ),
    # Django DEBUG
    (
        r"""(?i)^DEBUG\s*=\s*True\s*$""",
        "Django DEBUG=True — exposes sensitive information in error pages",
    ),
    # Node.js debug
    (
        r"""(?i)(?:NODE_ENV|NODE_DEBUG)\s*[:=]\s*['"]development['"]""",
        "NODE_ENV set to development — should be 'production' in production",
    ),
]


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for CORS and debug mode issues."""
    findings: list[Finding] = []
    
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        
        # Check CORS patterns
        for pattern, message in CORS_PATTERNS:
            match = re.search(pattern, line)
            if match:
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                
                findings.append(
                    Finding(
                        rule_id="VGB-004",
                        severity=Severity.HIGH,
                        message=message,
                        file=str(path),
                        line=line_num,
                        column=match.start() + 1,
                        snippet=snippet,
                        fix_hint="Restrict CORS origins to specific trusted domains",
                    )
                )
        
        # Check debug patterns
        for pattern, message in DEBUG_PATTERNS:
            match = re.search(pattern, line)
            if match:
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                
                findings.append(
                    Finding(
                        rule_id="VGB-005",
                        severity=Severity.MEDIUM,
                        message=message,
                        file=str(path),
                        line=line_num,
                        column=match.start() + 1,
                        snippet=snippet,
                        fix_hint="Set DEBUG=False and NODE_ENV=production for production deployments",
                    )
                )
    
    return findings
