"""Dangerous function usage detection (eval, exec, os.system)."""

import re
from pathlib import Path

from ..models import Finding, Severity

MAX_LINE_LENGTH = 50_000  # 50 KB

# Pre-compiled dangerous function patterns.
DANGEROUS_PATTERNS = [
    # Python eval()
    (
        re.compile(r"""(?<![\w])eval\s*\(\s*(?:request|req|input|params|body|data|user)"""),
        "eval() called with user input — arbitrary code execution vulnerability",
    ),
    # Python exec()
    (
        re.compile(r"""(?<![\w])exec\s*\(\s*(?:request|req|input|params|body|data|user)"""),
        "exec() called with user input — arbitrary code execution vulnerability",
    ),
    # Python os.system()
    (
        re.compile(r"""(?<![\w])os\.system\s*\(\s*(?:request|req|input|params|body|data|user)"""),
        "os.system() called with user input — command injection vulnerability",
    ),
    # Python subprocess with shell=True
    (
        re.compile(r"""(?<![\w])subprocess\.(?:run|call|Popen)\s*\(.*shell\s*=\s*True"""),
        "subprocess with shell=True — command injection risk if user input reaches it",
    ),
    # JavaScript eval()
    (
        re.compile(r"""(?<![\w])eval\s*\(\s*(?:req|request|params|query|body|user)"""),
        "eval() called with user input — arbitrary code execution vulnerability",
    ),
    # JavaScript Function() constructor
    (
        re.compile(r"""(?<![\w])new\s+Function\s*\(\s*(?:req|request|params|query|body|user)"""),
        "Function() constructor with user input — arbitrary code execution vulnerability",
    ),
    # Go exec.Command with fmt.Sprintf
    (
        re.compile(r"""exec\.Command\s*\([^)]*fmt\.Sprintf"""),
        "exec.Command with fmt.Sprintf — potential command injection",
    ),
]


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for dangerous function usage."""
    findings: list[Finding] = []
    
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        
        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]

        for compiled, message in DANGEROUS_PATTERNS:
            match = compiled.search(line)
            if match:
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:120] + "..."
                
                findings.append(
                    Finding(
                        rule_id="VGB-003",
                        severity=Severity.CRITICAL,
                        message=message,
                        file=str(path),
                        line=line_num,
                        column=match.start() + 1,
                        snippet=snippet,
                        fix_hint="Avoid eval/exec with user input. Use safe alternatives like ast.literal_eval() or dedicated parsers",
                    )
                )
    
    return findings
