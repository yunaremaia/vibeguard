"""VibeGuard rule registry and scanner orchestrator."""

from pathlib import Path

from .models import ScanResult, SUPPORTED_EXTENSIONS, SKIP_PATTERNS
from .rules.secrets import scan_file as scan_secrets
from .rules.sql_injection import scan_file as scan_sql_injection
from .rules.dangerous_functions import scan_file as scan_dangerous
from .rules.cors_debug import scan_file as scan_cors_debug
from .rules.missing_auth import scan_file as scan_missing_auth

# All rule functions
RULES = [
    scan_secrets,
    scan_sql_injection,
    scan_dangerous,
    scan_cors_debug,
    scan_missing_auth,
]


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB default cap


def should_scan(path: Path) -> bool:
    """Check if a file should be scanned."""
    if path.suffix not in SUPPORTED_EXTENSIONS:
        return False
    
    # Check skip patterns
    for part in path.parts:
        if part in SKIP_PATTERNS:
            return False
    
    return True


def scan_file(path: Path) -> list:
    """Scan a single file with all rules."""
    findings = []
    for rule_fn in RULES:
        try:
            findings.extend(rule_fn(path))
        except Exception:
            # Don't let one rule crash the scan
            continue
    return findings


def scan_directory(target: Path, max_size: int = 10 * 1024 * 1024) -> ScanResult:
    """Scan a directory recursively, rejecting symlinks that escape the target.

    Args:
        target: File or directory to scan.
        max_size: Maximum file size in bytes. Files larger than this are skipped
            to prevent OOM on huge files (default 10 MB).
    """
    result = ScanResult(target=str(target))

    # Resolve the target directory to prevent path traversal via symlinks
    try:
        resolved_target = target.resolve()
    except (OSError, RuntimeError):
        resolved_target = target

    if target.is_file():
        if should_scan(target):
            # SECURITY: skip oversized single files
            try:
                if target.stat().st_size > max_size:
                    return result
            except OSError:
                pass
            result.files_scanned = 1
            try:
                content = target.read_text(encoding="utf-8", errors="ignore")
                result.lines_scanned = len(content.splitlines())
            except Exception:
                pass
            result.findings = scan_file(target)
        return result

    # Walk directory
    for path in target.rglob("*"):
        if not path.is_file():
            continue

        # SECURITY: Reject symlinks that point outside the target directory
        # This prevents path traversal attacks via crafted symlinks
        try:
            if path.is_symlink():
                resolved = path.resolve()
                if not resolved.is_relative_to(resolved_target):
                    continue
        except (OSError, RuntimeError):
            continue

        if not should_scan(path):
            continue

        # SECURITY: Skip files larger than MAX_FILE_SIZE to avoid OOM
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue

        result.files_scanned += 1

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            result.lines_scanned += len(content.splitlines())
        except Exception:
            continue

        result.findings.extend(scan_file(path))

    return result
