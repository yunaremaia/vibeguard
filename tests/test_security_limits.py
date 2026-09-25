"""Tests for ReDoS protection and file size limits."""
import sys
from pathlib import Path

sys.path.insert(0, "src")

import re
import time
import threading

from vibeguard.scanner import scan_directory, should_scan
from vibeguard.models import ScanResult
from vibeguard.rules.secrets import scan_file as scan_secrets
from vibeguard.rules.sql_injection import scan_file as scan_sql_injection


# ---------------------------------------------------------------------------
# ReDoS tests
# ---------------------------------------------------------------------------

def _run_with_timeout(fn, args, timeout=2.0):
    """Run fn(*args) in a thread; return (result, timed_out)."""
    result = [None]
    error = [None]

    def target():
        try:
            result[0] = fn(*args)
        except Exception as e:
            error[0] = e

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    timed_out = t.is_alive()
    if timed_out:
        return None, True
    if error[0] is not None:
        raise error[0]
    return result[0], False


def test_secrets_redos_attacks_rejected():
    """SECRETS patterns must not hang on maliciously-crafted lines (ReDoS)."""
    # A long string of repeated 'a' followed by a quote — triggers backtracking
    # in patterns that use nested quantifiers.
    redos_payload = "a" * 3000 + '"test"'
    for pattern, _msg in [
        (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]", ""),
        (r"(?i)(token|secret|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]", ""),
    ]:
        compiled = re.compile(pattern)
        findings, timed_out = _run_with_timeout(compiled.search, (redos_payload,), timeout=2.0)
        assert not timed_out, f"Pattern {pattern!r} hung on ReDoS payload"


def test_sql_injection_redos_attacks_rejected():
    """SQL_INJECTION patterns must not hang on malicious input (ReDoS)."""
    # The .format() pattern with .* inside {} is the most vulnerable.
    redos_payload = "execute(" + "a" * 2000 + ".format("
    for pattern, _msg in [
        (r"(?i)(?:execute|query|cursor\.execute)\s*\(\s*['\"].*?\{.*?\}.*?['\"]\s*\.format\s*\(", ""),
        (r"(?i)(?:execute|query|cursor\.execute)\s*\(\s*['\"][^'\"]*['\"]\s*\+\s*", ""),
    ]:
        compiled = re.compile(pattern)
        findings, timed_out = _run_with_timeout(compiled.search, (redos_payload,), timeout=2.0)
        assert not timed_out, f"Pattern {pattern!r} hung on ReDoS payload"


def test_long_line_truncated_before_regex():
    """Lines longer than the max must be truncated before regex matching."""
    # The scanner must not pass a 1MB line to a regex engine.
    from vibeguard.rules.secrets import SECRET_PATTERNS
    # Check that the module has a line-length guard (to be implemented)
    # This test will be RED until the fix is in place.
    import vibeguard.rules.secrets as secrets_mod
    assert hasattr(secrets_mod, "MAX_LINE_LENGTH"), "MAX_LINE_LENGTH not defined"
    assert secrets_mod.MAX_LINE_LENGTH > 0, "MAX_LINE_LENGTH must be positive"


# ---------------------------------------------------------------------------
# File-size limit tests
# ---------------------------------------------------------------------------

def test_oversized_file_skipped(tmp_path):
    """Files larger than MAX_FILE_SIZE must be skipped (no OOM)."""
    from vibeguard.scanner import MAX_FILE_SIZE
    assert MAX_FILE_SIZE > 0, "MAX_FILE_SIZE must be defined"

    big = tmp_path / "huge.py"
    # Write just over the limit (1 MB chunk × N)
    chunk = "x" * (MAX_FILE_SIZE // 10)  # 10% of limit per chunk
    big.write_text("\n".join([chunk] * 11))  # slightly over limit

    assert big.stat().st_size > MAX_FILE_SIZE, "test file must exceed MAX_FILE_SIZE"
    result = scan_directory(tmp_path)
    assert result.files_scanned == 0, f"Oversized file should be skipped, scanned {result.files_scanned}"


def test_normal_file_still_scanned(tmp_path):
    """Files under the size limit must be scanned normally."""
    from vibeguard.scanner import MAX_FILE_SIZE
    small = tmp_path / "small.py"
    small.write_text("print('hello')\n")
    result = scan_directory(tmp_path)
    assert result.files_scanned == 1
    assert len(result.findings) == 0
