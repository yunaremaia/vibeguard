"""SQL injection via string formatting detection."""

import re
from pathlib import Path

from ..models import Finding, Severity

# Patterns for SQL injection vulnerabilities
SQL_INJECTION_PATTERNS = [
    # Python f-strings in SQL
    (
        r"""(?i)(?:execute|query|cursor\.execute)\s*\(\s*f['"]""",
        "SQL query uses f-string formatting — vulnerable to SQL injection",
    ),
    # Python .format() in SQL
    (
        r"""(?i)(?:execute|query|cursor\.execute)\s*\(\s*['"].*?\{.*?\}.*?['"]\s*\.format\s*\(""",
        "SQL query uses .format() — vulnerable to SQL injection",
    ),
    # Python % formatting in SQL
    (
        r"""(?i)(?:execute|query|cursor\.execute)\s*\(\s*['"].*?%s.*?['"]\s*%\s*""",
        "SQL query uses % formatting — use parameterized queries instead",
    ),
    # JavaScript template literals in SQL
    (
        r"""(?i)(?:query|execute|run)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`""",
        "SQL query uses template literal interpolation — vulnerable to SQL injection",
    ),
    # String concatenation in SQL
    (
        r"""(?i)(?:execute|query|cursor\.execute)\s*\(\s*['"][^'"]*['"]\s*\+\s*""",
        "SQL query uses string concatenation — vulnerable to SQL injection",
    ),
]


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for SQL injection patterns."""
    findings: list[Finding] = []
    
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        
        for pattern, message in SQL_INJECTION_PATTERNS:
            match = re.search(pattern, line)
            if match:
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                
                findings.append(
                    Finding(
                        rule_id="VGB-002",
                        severity=Severity.CRITICAL,
                        message=message,
                        file=str(path),
                        line=line_num,
                        column=match.start() + 1,
                        snippet=snippet,
                        fix_hint="Use parameterized queries (e.g., cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,)))",
                    )
                )
    
    return findings
