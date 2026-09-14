"""VibeGuard CLI entry point."""

import argparse
import sys
from pathlib import Path

from .scanner import scan_directory
from .formatters import format_text, format_json, format_sarif


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="vibeguard",
        description="Security scanner for AI-generated code",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="LOW",
        help="Minimum severity to report (default: LOW)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )
    
    args = parser.parse_args()
    
    target = Path(args.target)
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        return 2
    
    # Run scan
    result = scan_directory(target)
    
    # Filter by minimum severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_level = severity_order.get(args.min_severity, 3)
    result.findings = [
        f for f in result.findings
        if severity_order.get(f.severity.value, 99) <= min_level
    ]
    
    # Format output
    if args.format == "json":
        output = format_json(result)
    elif args.format == "sarif":
        output = format_sarif(result)
    else:
        output = format_text(result)
    
    # Write output
    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)
    
    # Return exit code based on findings
    return 1 if result.has_findings else 0


if __name__ == "__main__":
    sys.exit(main())
