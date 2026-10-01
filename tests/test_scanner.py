"""Behavioural tests for the scanner orchestrator.

Covers target dispatch (file vs directory), extension/skip filtering, the
per-rule failure isolation guarantee and the file-size guards.
"""

import logging
import os
import sys
from pathlib import Path

from vibeguard import scanner
from vibeguard.rules import cors_debug, dangerous_functions, missing_auth, secrets, sql_injection
from vibeguard.scanner import RULES, scan_directory, scan_file, should_scan


def _rule_module_name(rule_fn) -> str:
    return getattr(rule_fn, "__module__", "")


# ---------------------------------------------------------------------------
# should_scan
# ---------------------------------------------------------------------------


def test_should_scan_accepts_supported_extensions(tmp_path):
    for name in ("app.py", "index.js", "main.ts", "config.yaml", "Cargo.toml"):
        assert should_scan(tmp_path / name) is True, name


def test_should_scan_rejects_unsupported_extension(tmp_path):
    for name in ("notes.md", "image.png", "data.csv", "Makefile"):
        assert should_scan(tmp_path / name) is False, name


def test_should_scan_rejects_paths_inside_skip_patterns(tmp_path):
    """Vendored and VCS directories are never scanned."""
    for part in ("node_modules", ".git", "__pycache__", ".venv", "dist", "vendor"):
        assert should_scan(tmp_path / part / "app.py") is False, part


def test_should_scan_rejects_skipped_extension_before_skip_patterns(tmp_path):
    """A skipped directory with a supported extension is still rejected."""
    assert should_scan(Path("dist") / "bundle.js") is False


# ---------------------------------------------------------------------------
# scan_file: rule isolation
# ---------------------------------------------------------------------------


def test_scan_file_runs_every_registered_rule(vulnerable_file):
    """All five rules are applied, so findings from each show up."""
    rule_ids = {f.rule_id for f in scan_file(vulnerable_file)}
    assert {"VGB-001", "VGB-002", "VGB-005", "VGB-006"} <= rule_ids


def test_scan_file_isolates_a_failing_rule(monkeypatch, vulnerable_file, caplog):
    """One crashing rule must not abort the scan or lose the other findings."""

    def exploding_rule(path: Path):
        raise RuntimeError("rule blew up")

    monkeypatch.setattr(
        scanner, "RULES", [exploding_rule, secrets.scan_file, sql_injection.scan_file]
    )
    with caplog.at_level(logging.DEBUG, logger=scanner.__name__):
        findings = scan_file(vulnerable_file)
    # The healthy rules still produced their CRITICAL finding...
    assert "VGB-001" in {f.rule_id for f in findings}
    # ...and the failure was recorded rather than swallowed silently.
    messages = [r.getMessage() for r in caplog.records]
    assert any("rule" in m and "failed on" in m for m in messages)
    assert any(r.exc_info is not None for r in caplog.records)


def test_scan_file_returns_empty_list_when_all_rules_fail(monkeypatch, clean_file):
    """If every rule raises, the scan yields no findings instead of crashing."""

    def exploding_rule(path: Path):
        raise RuntimeError("boom")

    monkeypatch.setattr(scanner, "RULES", [exploding_rule, exploding_rule])
    assert scan_file(clean_file) == []


# ---------------------------------------------------------------------------
# scan_directory: file targets
# ---------------------------------------------------------------------------


def test_scan_directory_accepts_a_single_file_target(vulnerable_file):
    """Passing a file scans just that file and reports its line count."""
    result = scan_directory(vulnerable_file)
    assert result.target == str(vulnerable_file)
    assert result.files_scanned == 1
    assert result.lines_scanned == len(vulnerable_file.read_text(encoding="utf-8").splitlines())
    assert result.findings


def test_scan_directory_ignores_single_file_with_unsupported_extension(tmp_path):
    """A .md target is not scanned and not counted."""
    notes = tmp_path / "notes.md"
    notes.write_text('API_KEY = "REDACTEDFAKEKEYDONTUSE0000"\n', encoding="utf-8")
    result = scan_directory(notes)
    assert result.files_scanned == 0
    assert result.findings == []


def test_scan_directory_skips_oversized_single_file_via_max_size(vulnerable_file):
    """A max_size smaller than the file skips it even for a file target."""
    result = scan_directory(vulnerable_file, max_size=1)
    assert result.files_scanned == 0
    assert result.findings == []


# ---------------------------------------------------------------------------
# scan_directory: directory targets
# ---------------------------------------------------------------------------


def test_scan_directory_walks_recursively_and_counts_lines(tmp_path):
    """Every supported file below the target is scanned, dirs skipped."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    (tmp_path / "b.js").write_text("const x = 1\n", encoding="utf-8")
    (tmp_path / "empty").mkdir()  # a directory, not a file: must be skipped

    result = scan_directory(tmp_path)
    assert result.files_scanned == 2
    assert result.lines_scanned == 3
    assert not result.has_findings


def test_scan_directory_skips_nested_skip_patterns(tmp_path):
    """node_modules anywhere in the tree is pruned."""
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text("a = 1\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("b = 2\n", encoding="utf-8")

    result = scan_directory(tmp_path)
    assert result.files_scanned == 1
    assert result.lines_scanned == 1


def test_scan_directory_skips_unsupported_files_in_tree(tmp_path):
    """A .md file in the tree is ignored and not counted."""
    (tmp_path / "README.md").write_text("# hi\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("a = 1\n", encoding="utf-8")
    result = scan_directory(tmp_path)
    assert result.files_scanned == 1


def test_scan_directory_enforces_module_level_max_file_size(monkeypatch, tmp_path):
    """The hard MAX_FILE_SIZE cap applies to files in a directory walk."""
    monkeypatch.setattr(scanner, "MAX_FILE_SIZE", 10)
    (tmp_path / "big.py").write_text("x = 1234567890\n", encoding="utf-8")  # 14 bytes
    (tmp_path / "small.py").write_text("y = 1\n", encoding="utf-8")  # 6 bytes
    result = scan_directory(tmp_path)
    assert result.files_scanned == 1
    assert result.lines_scanned == 1


def test_scan_directory_reports_findings_from_every_rule(tmp_path):
    """An end-to-end scan surfaces findings from all applicable rules."""
    (tmp_path / "app.py").write_text(
        'API_KEY = "REDACTEDFAKEKEYDONTUSE0000"\nDEBUG = True\n', encoding="utf-8"
    )
    result = scan_directory(tmp_path)
    assert result.has_findings
    assert {"VGB-001", "VGB-005"} <= {f.rule_id for f in result.findings}
    # Every finding must point at the real file that triggered it.
    assert {f.file for f in result.findings} == {str(tmp_path / "app.py")}


def test_scan_directory_accepts_relative_path_target(tmp_path, monkeypatch):
    """A relative target works and is reported as given."""
    (tmp_path / "app.py").write_text("a = 1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = scan_directory(Path("."))
    assert result.files_scanned == 1
    assert result.target == "."


# ---------------------------------------------------------------------------
# Rule-level: unreadable input
# ---------------------------------------------------------------------------


def test_rules_return_no_findings_for_missing_file(tmp_path):
    """Every rule tolerates a file that cannot be read."""
    missing = tmp_path / "gone.py"
    for rule in (secrets, sql_injection, dangerous_functions, cors_debug, missing_auth):
        assert rule.scan_file(missing) == [], rule.__name__


def test_all_rules_are_registered_in_scanner():
    """The registry contains exactly the five shipped rules."""
    assert set(RULES) == {
        secrets.scan_file,
        sql_injection.scan_file,
        dangerous_functions.scan_file,
        cors_debug.scan_file,
        missing_auth.scan_file,
    }
    assert all(callable(r) for r in RULES)
    assert all(_rule_module_name(r) for r in RULES)


# ---------------------------------------------------------------------------
# I/O error tolerance
#
# The scanner documents that a malformed or vanishing file must never abort a
# scan. These make a single path fail at the exact call site and assert the
# scan still returns a usable result.
#
# The injection is scoped to calls that originate in scanner.py. On Python
# <= 3.12 both Path.resolve() and Path.is_file() call Path.stat() internally,
# so an unscoped patch would break one of those *unguarded* calls before ever
# reaching the guarded one. Scoping by caller keeps the test honest and makes
# it behave identically on every supported interpreter.
# ---------------------------------------------------------------------------


def _fail_from_scanner_only(monkeypatch, method: str, target: Path, exc: Exception) -> None:
    """Make ``Path.<method>`` raise *exc* for *target*, but only when the
    caller is vibeguard's scanner module."""
    original = getattr(Path, method)
    # Normalised on both sides: a co_filename recorded via a relative sys.path
    # entry would otherwise not match an absolute __file__.
    scanner_file = os.path.abspath(scanner.__file__)

    def patched(self, *args, **kwargs):
        caller = sys._getframe(1).f_code.co_filename
        if self == target and os.path.abspath(caller) == scanner_file:
            raise exc
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, method, patched)


def test_scan_directory_survives_a_stat_failure(monkeypatch, tmp_path):
    """A file that cannot be stat'ed is skipped; its neighbours still scan."""
    (tmp_path / "ok.py").write_text("a = 1\n", encoding="utf-8")
    broken = tmp_path / "broken.py"
    broken.write_text("b = 2\n", encoding="utf-8")
    _fail_from_scanner_only(monkeypatch, "stat", broken, OSError("vanished"))

    result = scan_directory(tmp_path)
    assert result.files_scanned == 1
    assert result.lines_scanned == 1


def test_scan_directory_survives_a_read_failure(monkeypatch, tmp_path):
    """An unreadable file is skipped, not fatal; other files are unaffected.

    Note ``files_scanned`` is incremented *before* the read, so a file that
    fails to read is still counted as scanned. What matters is that it
    contributes no lines and no findings, and that the scan completes.
    """
    (tmp_path / "ok.py").write_text("a = 1\n", encoding="utf-8")
    broken = tmp_path / "broken.py"
    broken.write_text('API_KEY = "REDACTEDFAKEKEYDONTUSE0000"\n', encoding="utf-8")
    _fail_from_scanner_only(monkeypatch, "read_text", broken, OSError("permission denied"))

    result = scan_directory(tmp_path)
    assert result.lines_scanned == 1, "the unreadable file must contribute no lines"
    assert result.findings == [], "the unreadable file must not be handed to the rules"


def test_scan_directory_survives_a_symlink_resolve_failure(monkeypatch, tmp_path):
    """A symlink whose target cannot be resolved is skipped, not fatal."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("a = 1\n", encoding="utf-8")
    link = project / "link.py"
    link.symlink_to(project / "app.py")
    _fail_from_scanner_only(monkeypatch, "resolve", link, RuntimeError("symlink loop"))

    result = scan_directory(project)
    assert result.files_scanned == 1


def test_scan_directory_survives_a_target_resolve_failure(monkeypatch, tmp_path):
    """If the target itself cannot be resolved, the scan still runs."""
    (tmp_path / "app.py").write_text("a = 1\n", encoding="utf-8")
    _fail_from_scanner_only(monkeypatch, "resolve", tmp_path, OSError("cannot resolve"))

    result = scan_directory(tmp_path)
    assert result.files_scanned == 1


def test_single_file_scan_survives_stat_and_read_failures(monkeypatch, vulnerable_file):
    """A single-file target that cannot be stat'ed or read still returns."""
    _fail_from_scanner_only(monkeypatch, "stat", vulnerable_file, OSError("vanished"))
    result = scan_directory(vulnerable_file)
    # The size check failed, so the file is still scanned.
    assert result.files_scanned == 1

    monkeypatch.undo()
    _fail_from_scanner_only(monkeypatch, "read_text", vulnerable_file, OSError("denied"))
    result = scan_directory(vulnerable_file)
    assert result.files_scanned == 1
    assert result.lines_scanned == 0
