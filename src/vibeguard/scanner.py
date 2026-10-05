"""VibeGuard rule registry and scanner orchestrator."""

import logging
from pathlib import Path

from .models import SKIP_PATTERNS, SUPPORTED_EXTENSIONS, ScanResult
from .rules.client_side import scan_file as scan_client_side
from .rules.cors_debug import scan_file as scan_cors_debug
from .rules.dangerous_functions import scan_file as scan_dangerous
from .rules.insecure_design import scan_file as scan_insecure_design
from .rules.missing_auth import scan_file as scan_missing_auth
from .rules.secret_entropy import scan_file as scan_secret_entropy
from .rules.secrets import scan_file as scan_secrets
from .rules.sql_injection import scan_file as scan_sql_injection

# All rule functions
RULES = [
    scan_secrets,
    scan_secret_entropy,
    scan_sql_injection,
    scan_dangerous,
    scan_cors_debug,
    scan_missing_auth,
    scan_insecure_design,
    scan_client_side,
]


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB default cap

logger = logging.getLogger(__name__)


def should_scan(path: Path, base: Path | None = None) -> bool:
    """Check if a file should be scanned.

    ``base`` is the scan target. Skip patterns are matched against the
    components of ``path`` *relative to* ``base``, so a project that merely
    lives under an ancestor named ``build/`` is still scanned (#128). Without
    ``base`` every component is matched, as before.
    """
    # A leading dot starts the file name, not an extension: Path(".env").suffix
    # is "" and Path(".env.local").suffix is ".local". Gate the dotenv family
    # by name, then fall through to the extension check (#127).
    if not (path.name == ".env" or path.name.startswith(".env.")):
        if path.suffix not in SUPPORTED_EXTENSIONS:
            return False

    # Check skip patterns
    if base is not None:
        try:
            parts = path.relative_to(base).parts
        except ValueError:
            parts = path.parts
    else:
        parts = path.parts
    for part in parts:
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
            # A malformed file can raise anything inside a rule. One bad rule
            # must not abort the whole scan, so the failure is recorded at
            # debug level rather than discarded without a trace.
            logger.debug("rule %s failed on %s", getattr(rule_fn, "__module__", rule_fn), path, exc_info=True)
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
            except (OSError, ValueError, UnicodeDecodeError):
                logger.debug("could not read %s", target, exc_info=True)
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

        if not should_scan(path, base=target):
            continue

        # SECURITY: Skip files larger than the cap to avoid OOM. The hard
        # MAX_FILE_SIZE ceiling still applies on top of the caller's max_size.
        try:
            if path.stat().st_size > min(max_size, MAX_FILE_SIZE):
                continue
        except OSError:
            continue

        result.files_scanned += 1

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            result.lines_scanned += len(content.splitlines())
        except (OSError, ValueError, UnicodeDecodeError):
            logger.debug("could not read %s", path, exc_info=True)
            continue

        result.findings.extend(scan_file(path))

    return result
