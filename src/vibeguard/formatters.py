"""Output formatters for VibeGuard."""

import json
from datetime import datetime, timezone

from .models import ScanResult, Severity


def format_text(result: ScanResult) -> str:
    """Format results as colored text for terminal output."""
    lines: list[str] = []
    
    # Header
    lines.append("=" * 70)
    lines.append("VibeGuard Security Scan Report")
    lines.append("=" * 70)
    lines.append(f"Target: {result.target}")
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Lines scanned: {result.lines_scanned}")
    lines.append(f"Findings: {len(result.findings)}")
    lines.append("")
    
    if not result.findings:
        lines.append("✅ No security issues found!")
        lines.append("")
        return "\n".join(lines)
    
    # Summary by severity
    by_sev = result.by_severity()
    lines.append("Summary:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = len(by_sev.get(sev, []))
        if count > 0:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}[sev]
            lines.append(f"  {icon} {sev}: {count}")
    lines.append("")
    
    # Detailed findings
    lines.append("-" * 70)
    lines.append("Detailed Findings:")
    lines.append("-" * 70)
    
    # Sort by severity
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 99))
    
    for i, finding in enumerate(sorted_findings, 1):
        sev_icon = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
        }.get(finding.severity, "⚪")
        
        lines.append(f"\n[{i}] {sev_icon} {finding.rule_id} — {finding.severity.value}")
        lines.append(f"    File: {finding.file}:{finding.line}")
        lines.append(f"    Issue: {finding.message}")
        if finding.snippet:
            lines.append(f"    Code: {finding.snippet}")
        if finding.fix_hint:
            lines.append(f"    Fix: {finding.fix_hint}")
    
    lines.append("")
    lines.append("-" * 70)
    lines.append(f"Total: {len(result.findings)} issue(s) found")
    lines.append("")
    
    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    """Format results as JSON."""
    output = {
        "tool": {
            "name": "VibeGuard",
            "version": "0.1.0",
        },
        "scan": {
            "target": result.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "files_scanned": result.files_scanned,
            "lines_scanned": result.lines_scanned,
        },
        "summary": {
            "total": len(result.findings),
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": sum(1 for f in result.findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in result.findings if f.severity == Severity.LOW),
        },
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(output, indent=2)


def format_sarif(result: ScanResult) -> str:
    """Format results as SARIF (Static Analysis Results Interchange Format)."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VibeGuard",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/yunaremaia/vibeguard",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }
    
    # Collect unique rules
    rules_map: dict[str, dict] = {}
    for f in result.findings:
        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.message},
                "help": {"text": f.fix_hint},
                "defaultConfiguration": {
                    "level": _sarif_level(f.severity),
                },
            }
    
    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())
    
    # Add results
    for f in result.findings:
        sarif["runs"][0]["results"].append(
            {
                "ruleId": f.rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column,
                                "snippet": {"text": f.snippet},
                            },
                        }
                    }
                ],
            }
        )
    
    return json.dumps(sarif, indent=2)


def _sarif_level(severity: Severity) -> str:
    """Convert VibeGuard severity to SARIF level."""
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }
    return mapping.get(severity, "warning")
