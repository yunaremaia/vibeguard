"""Behavioural tests for the output formatters.

These assert on the *content* of the rendered output (counts, ordering,
SARIF/JSON structure) because that is the contract downstream tooling
consumes, not on incidental whitespace.
"""

import json
from datetime import datetime

from vibeguard.formatters import format_json, format_sarif, format_text
from vibeguard.models import ScanResult, Severity

# ---------------------------------------------------------------------------
# format_text
# ---------------------------------------------------------------------------


def test_text_report_header_reports_scan_totals():
    """The report always states the target and how much was scanned."""
    result = ScanResult(target="/srv/app", files_scanned=4, lines_scanned=137)
    out = format_text(result)
    assert "VibeGuard Security Scan Report" in out
    assert "Target: /srv/app" in out
    assert "Files scanned: 4" in out
    assert "Lines scanned: 137" in out


def test_text_report_with_no_findings_stops_early():
    """A clean scan short-circuits instead of printing an empty table."""
    out = format_text(ScanResult(target="/srv/app", files_scanned=2, lines_scanned=8))
    assert "✅ No security issues found!" in out
    # The detailed-findings section must not appear for a clean scan.
    assert "Detailed Findings:" not in out
    assert "Total:" not in out


def test_text_report_lists_findings_with_file_line_and_message():
    """Each finding is rendered with its location, issue, code and fix."""
    from vibeguard.models import Finding

    finding = Finding(
        rule_id="VGB-001",
        severity=Severity.CRITICAL,
        message="Hardcoded API key detected",
        file="app.py",
        line=42,
        column=7,
        snippet='API_KEY = "abcdefghij0123456789"',
        fix_hint="Use environment variables",
    )
    out = format_text(ScanResult(target="/srv/app", findings=[finding]))
    assert "[1] 🔴 VGB-001 — CRITICAL" in out
    assert "File: app.py:42" in out
    assert "Issue: Hardcoded API key detected" in out
    assert 'Code: API_KEY = "abcdefghij0123456789"' in out
    assert "Fix: Use environment variables" in out
    assert "Total: 1 issue(s) found" in out


def test_text_report_orders_findings_critical_first():
    """Findings are sorted most-severe-first, regardless of input order."""
    from vibeguard.models import Finding

    def finding(rule_id, severity):
        return Finding(
            rule_id=rule_id,
            severity=severity,
            message="m",
            file="f.py",
            line=1,
            snippet="x",
            fix_hint="y",
        )

    findings = [
        finding("VGB-LOW", Severity.LOW),
        finding("VGB-MED", Severity.MEDIUM),
        finding("VGB-CRIT", Severity.CRITICAL),
        finding("VGB-HIGH", Severity.HIGH),
    ]
    out = format_text(ScanResult(target="/srv/app", findings=findings))
    order = [out.index("[1]"), out.index("[2]"), out.index("[3]"), out.index("[4]")]
    assert order == sorted(order), "numbered findings must be severity-ordered"
    for index, (rule_id, icon) in enumerate(
        [
            ("VGB-CRIT", "🔴"),
            ("VGB-HIGH", "🟠"),
            ("VGB-MED", "🟡"),
            ("VGB-LOW", "🔵"),
        ],
        1,
    ):
        assert f"[{index}] {icon} {rule_id}" in out


def test_text_report_summary_counts_only_present_severities():
    """The summary block omits severities with a zero count."""
    from vibeguard.models import Finding

    findings = [
        Finding("VGB-001", Severity.CRITICAL, "m", "f.py"),
        Finding("VGB-004", Severity.HIGH, "m", "f.py"),
        Finding("VGB-006", Severity.HIGH, "m", "f.py"),
    ]
    out = format_text(ScanResult(target="/srv/app", findings=findings))
    assert "Summary:" in out
    assert "🔴 CRITICAL: 1" in out
    assert "🟠 HIGH: 2" in out
    # MEDIUM and LOW have no findings, so they must not be listed.
    assert "MEDIUM:" not in out
    assert "LOW:" not in out


def test_text_report_omits_code_and_fix_lines_when_empty():
    """Empty snippet/fix_hint do not produce dangling "Code:"/"Fix:" lines."""
    from vibeguard.models import Finding

    bare = Finding("VGB-002", Severity.MEDIUM, "m", "f.py", line=3, snippet="", fix_hint="")
    out = format_text(ScanResult(target="/srv/app", findings=[bare]))
    assert "Code:" not in out
    assert "Fix:" not in out
    assert "File: f.py:3" in out


# ---------------------------------------------------------------------------
# format_json
# ---------------------------------------------------------------------------


def test_json_report_is_valid_json_with_tool_and_scan_metadata():
    """The JSON report parses and carries a timestamp plus scan metadata."""
    result = ScanResult(target="/srv/app", files_scanned=3, lines_scanned=42)
    payload = json.loads(format_json(result))
    assert payload["tool"] == {"name": "VibeGuard", "version": "0.1.0"}
    assert payload["scan"]["target"] == "/srv/app"
    assert payload["scan"]["files_scanned"] == 3
    assert payload["scan"]["lines_scanned"] == 42
    # The timestamp must be an ISO-8601 instant we can parse back.
    assert datetime.fromisoformat(payload["scan"]["timestamp"]).tzinfo is not None


def test_json_summary_counts_match_findings():
    """Every summary counter agrees with the findings actually reported."""
    from vibeguard.models import Finding

    findings = [
        Finding("VGB-001", Severity.CRITICAL, "c", "f.py"),
        Finding("VGB-002", Severity.CRITICAL, "c", "f.py"),
        Finding("VGB-004", Severity.HIGH, "h", "f.py"),
        Finding("VGB-005", Severity.MEDIUM, "m", "f.py"),
        Finding("VGB-005", Severity.MEDIUM, "m", "f.py"),
        Finding("VGB-LOW", Severity.LOW, "l", "f.py"),
    ]
    payload = json.loads(format_json(ScanResult(target="/srv/app", findings=findings)))
    assert payload["summary"] == {"total": 6, "critical": 2, "high": 1, "medium": 2, "low": 1}
    assert len(payload["findings"]) == 6


def test_json_findings_are_serialised_finding_dicts():
    """Findings are emitted in the full public dict shape."""
    from vibeguard.models import Finding

    finding = Finding(
        "VGB-003", Severity.HIGH, "boom", "src/app.py", 12, 5, "eval(x)", "stop doing that"
    )
    payload = json.loads(format_json(ScanResult(target="/srv/app", findings=[finding])))
    assert payload["findings"] == [
        {
            "rule_id": "VGB-003",
            "severity": "HIGH",
            "message": "boom",
            "file": "src/app.py",
            "line": 12,
            "column": 5,
            "snippet": "eval(x)",
            "fix_hint": "stop doing that",
        }
    ]


# ---------------------------------------------------------------------------
# format_sarif
# ---------------------------------------------------------------------------


def test_sarif_envelope_is_schema_conformant():
    """Top-level SARIF 2.1.0 fields identify the tool."""
    payload = json.loads(format_sarif(ScanResult(target="/srv/app")))
    assert payload["version"] == "2.1.0"
    assert payload["$schema"].endswith("sarif-schema-2.1.0.json")
    driver = payload["runs"][0]["tool"]["driver"]
    assert driver["name"] == "VibeGuard"
    assert driver["version"] == "0.1.0"
    assert driver["informationUri"] == "https://github.com/yunaremaia/vibeguard"
    assert payload["runs"][0]["results"] == []


def test_sarif_deduplicates_rules_and_keeps_first_occurrence_order():
    """One rule entry per rule_id, even when several findings share it."""
    from vibeguard.models import Finding

    findings = [
        Finding("VGB-001", Severity.CRITICAL, "first message", "a.py", 1, 1, "s1", "fix one"),
        Finding("VGB-004", Severity.HIGH, "second message", "b.py", 2, 1, "s2", "fix two"),
        Finding("VGB-001", Severity.CRITICAL, "later message", "c.py", 3, 1, "s3", "fix three"),
    ]
    rules = json.loads(format_sarif(ScanResult(target="/srv/app", findings=findings)))[
        "runs"
    ][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["VGB-001", "VGB-004"]
    # The first occurrence wins, so the description stays stable.
    assert rules[0]["shortDescription"]["text"] == "first message"
    assert rules[0]["help"]["text"] == "fix one"


def test_sarif_maps_severity_to_level_and_location():
    """Each result carries a SARIF level and a physical location."""
    from vibeguard.models import Finding

    findings = [
        Finding("VGB-001", Severity.CRITICAL, "c", "a.py", 1, 1, "s1", "f1"),
        Finding("VGB-004", Severity.HIGH, "h", "b.py", 2, 3, "s2", "f2"),
        Finding("VGB-005", Severity.MEDIUM, "m", "c.py", 3, 4, "s3", "f3"),
        Finding("VGB-LOW", Severity.LOW, "l", "d.py", 4, 5, "s4", "f4"),
    ]
    payload = json.loads(format_sarif(ScanResult(target="/srv/app", findings=findings)))
    results = payload["runs"][0]["results"]
    assert [r["level"] for r in results] == ["error", "error", "warning", "note"]
    assert [r["message"]["text"] for r in results] == ["c", "h", "m", "l"]

    region = results[1]["locations"][0]["physicalLocation"]["region"]
    artifact = results[1]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert artifact["uri"] == "b.py"
    assert region == {"startLine": 2, "startColumn": 3, "snippet": {"text": "s2"}}

    # Every rule's defaultConfiguration must agree with its results.
    levels = {
        rule["id"]: rule["defaultConfiguration"]["level"]
        for rule in payload["runs"][0]["tool"]["driver"]["rules"]
    }
    assert levels == {"VGB-001": "error", "VGB-004": "error", "VGB-005": "warning", "VGB-LOW": "note"}


def test_sarif_falls_back_to_warning_for_unknown_severity():
    """A severity outside the known set degrades to "warning", not a crash.

    Guards the default branch of the severity -> SARIF level mapping.
    """
    from vibeguard.models import Finding

    finding = Finding("VGB-999", "BOOM", "odd", "a.py", 1, 1, "s", "f")
    payload = json.loads(format_sarif(ScanResult(target="/srv/app", findings=[finding])))
    assert payload["runs"][0]["results"][0]["level"] == "warning"
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["defaultConfiguration"]["level"] == "warning"
