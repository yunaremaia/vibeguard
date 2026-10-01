"""Behavioural tests for the CLI entry point.

The CLI is exercised through ``main()`` with a patched ``sys.argv``, exactly as
a user's shell would drive it: argument parsing, target validation, severity
filtering, format selection, output destination and the exit code.
"""

import json
import runpy
import sys
from pathlib import Path

import pytest

from vibeguard.cli import main

# A project that trips one rule of each severity the scanner can emit:
# VGB-001 (CRITICAL, hardcoded key), VGB-004/006 (HIGH, CORS + missing auth)
# and VGB-005 (MEDIUM, debug mode).
MIXED_SEVERITY_SOURCE = """\
API_KEY = "REDACTEDFAKEKEYDONTUSE0000"
DEBUG = True


@app.get("/admin/panel")
def panel():
    return "ok"
"""


@pytest.fixture
def mixed_project(tmp_path: Path) -> Path:
    """A directory whose scan yields CRITICAL, HIGH and MEDIUM findings."""
    (tmp_path / "app.py").write_text(MIXED_SEVERITY_SOURCE, encoding="utf-8")
    return tmp_path


def run_cli(monkeypatch, *argv: str) -> int:
    """Invoke main() with the given argv, returning its exit code."""
    monkeypatch.setattr(sys, "argv", ["vibeguard", *argv])
    return main()


# ---------------------------------------------------------------------------
# Argument parsing / target validation
# ---------------------------------------------------------------------------


def test_missing_target_fails_with_exit_code_2(monkeypatch, capsys, tmp_path):
    """A non-existent target is a usage error: exit 2, message on stderr."""
    missing = tmp_path / "does-not-exist"
    assert run_cli(monkeypatch, str(missing)) == 2
    captured = capsys.readouterr()
    assert f"Error: {missing} does not exist" in captured.err
    assert captured.out == ""


def test_target_defaults_to_current_directory(monkeypatch, capsys, tmp_path):
    """With no target argument the CLI scans the working directory."""
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert run_cli(monkeypatch) == 0
    assert "Target: ." in capsys.readouterr().out


def test_clean_project_exits_zero(monkeypatch, capsys, clean_file):
    """A project with no findings is a success."""
    assert run_cli(monkeypatch, str(clean_file)) == 0
    assert "✅ No security issues found!" in capsys.readouterr().out


def test_project_with_findings_exits_one(monkeypatch, capsys, vulnerable_file):
    """Findings are reported on stdout and signal failure via exit code 1."""
    assert run_cli(monkeypatch, str(vulnerable_file)) == 1
    out = capsys.readouterr().out
    assert "VGB-001" in out
    assert "issue(s) found" in out


# ---------------------------------------------------------------------------
# Format selection
# ---------------------------------------------------------------------------


def test_json_format_emits_parseable_json(monkeypatch, capsys, vulnerable_file):
    """-f json writes nothing but valid JSON to stdout."""
    assert run_cli(monkeypatch, str(vulnerable_file), "-f", "json") == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"]["name"] == "VibeGuard"
    assert payload["summary"]["total"] == len(payload["findings"])
    assert {f["rule_id"] for f in payload["findings"]} >= {"VGB-001"}


def test_sarif_format_emits_sarif_envelope(monkeypatch, capsys, vulnerable_file):
    """-f sarif writes a SARIF 2.1.0 document."""
    assert run_cli(monkeypatch, str(vulnerable_file), "--format", "sarif") == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "VibeGuard"
    assert payload["runs"][0]["results"]


def test_unknown_format_is_rejected_by_argparse(monkeypatch, tmp_path):
    """The format argument only accepts the documented choices."""
    with pytest.raises(SystemExit) as excinfo:
        run_cli(monkeypatch, str(tmp_path), "-f", "xml")
    assert excinfo.value.code == 2


# ---------------------------------------------------------------------------
# Output destination
# ---------------------------------------------------------------------------


def test_output_flag_writes_to_file_instead_of_stdout(
    monkeypatch, capsys, tmp_path, vulnerable_file
):
    """-o redirects the report to disk and keeps stdout empty."""
    out_file = tmp_path / "report.json"
    assert run_cli(monkeypatch, str(vulnerable_file), "-f", "json", "-o", str(out_file)) == 1
    assert capsys.readouterr().out == ""
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["scan"]["target"] == str(vulnerable_file)


def test_output_flag_accepts_text_format_too(monkeypatch, tmp_path, vulnerable_file):
    """-o works for every format, not just JSON."""
    out_file = tmp_path / "report.txt"
    assert run_cli(monkeypatch, str(vulnerable_file), "-o", str(out_file)) == 1
    assert "VibeGuard Security Scan Report" in out_file.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Severity filtering
# ---------------------------------------------------------------------------


def test_default_min_severity_reports_everything(monkeypatch, capsys, mixed_project):
    """The default --min-severity LOW keeps CRITICAL, HIGH and MEDIUM findings."""
    run_cli(monkeypatch, str(mixed_project), "-f", "json")
    payload = json.loads(capsys.readouterr().out)
    assert {f["severity"] for f in payload["findings"]} == {"CRITICAL", "HIGH", "MEDIUM"}


def test_min_severity_high_drops_medium_and_lower(monkeypatch, capsys, mixed_project):
    """--min-severity HIGH keeps CRITICAL+HIGH and drops the MEDIUM findings."""
    run_cli(monkeypatch, str(mixed_project), "-f", "json", "--min-severity", "HIGH")
    payload = json.loads(capsys.readouterr().out)
    severities = {f["severity"] for f in payload["findings"]}
    assert severities == {"CRITICAL", "HIGH"}
    assert payload["summary"]["medium"] == 0
    assert payload["summary"]["total"] == len(payload["findings"])


def test_min_severity_medium_is_not_stricter_than_high(monkeypatch, capsys, mixed_project):
    """A lower minimum reports a superset: MEDIUM also keeps HIGH findings."""
    run_cli(monkeypatch, str(mixed_project), "-f", "json", "--min-severity", "MEDIUM")
    medium = json.loads(capsys.readouterr().out)
    assert {f["severity"] for f in medium["findings"]} == {"CRITICAL", "HIGH", "MEDIUM"}


def test_min_severity_critical_keeps_only_critical(monkeypatch, capsys, mixed_project):
    """--min-severity CRITICAL is the strictest report."""
    run_cli(monkeypatch, str(mixed_project), "-f", "json", "--min-severity", "CRITICAL")
    payload = json.loads(capsys.readouterr().out)
    assert {f["severity"] for f in payload["findings"]} == {"CRITICAL"}
    assert payload["summary"]["medium"] == 0


def test_min_severity_filter_applies_to_text_format(monkeypatch, capsys, mixed_project):
    """The filter is applied to the result, so text output honours it too."""
    run_cli(monkeypatch, str(mixed_project), "--min-severity", "CRITICAL")
    out = capsys.readouterr().out
    assert "VGB-001" in out
    assert "VGB-005" not in out


def test_min_severity_rejects_unknown_level(monkeypatch, tmp_path):
    """An unknown severity level is rejected by argparse."""
    with pytest.raises(SystemExit) as excinfo:
        run_cli(monkeypatch, str(tmp_path), "--min-severity", "SEVERE")
    assert excinfo.value.code == 2


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------


def test_module_entry_point_exits_with_main_return_code(monkeypatch, capsys, clean_file):
    """Running the module as __main__ turns main()'s return into an exit code."""
    monkeypatch.setattr(sys, "argv", ["vibeguard", str(clean_file)])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("vibeguard.cli", run_name="__main__")
    assert excinfo.value.code == 0
    assert "No security issues found!" in capsys.readouterr().out


def test_module_entry_point_exits_one_when_findings_exist(monkeypatch, capsys, vulnerable_file):
    """The __main__ path propagates the findings exit code as well."""
    monkeypatch.setattr(sys, "argv", ["vibeguard", str(vulnerable_file)])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("vibeguard.cli", run_name="__main__")
    assert excinfo.value.code == 1
