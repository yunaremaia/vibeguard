"""Detection rules for AI-generated code patterns."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    file: str
    line: int = 0
    column: int = 0
    snippet: str = ""
    fix_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "fix_hint": self.fix_hint,
        }


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.severity.value, []).append(f)
        return result


# File extensions we support
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb", ".php",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".env",
}

# Files/directories to skip
SKIP_PATTERNS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build",
    ".next", ".nuxt", "target", "vendor", ".tox", ".mypy_cache", ".pytest_cache",
}
