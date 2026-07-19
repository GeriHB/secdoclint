"""Command-line interface for running SecDocLint scans.

This module translates command-line arguments into a repository scan, renders the resulting findings, and returns shell-friendly exit codes.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .config import load_config
from .models import Finding, Severity
from .scanner import scan_repository

def build_parser() -> argparse.ArgumentParser:
    """Build and reurn the command-line argument parser.

    Returns:
        A configured parser containing the ``ckeck`` subcomand and its supported output, configuration, and severity options.
    """

    parser = argparse.ArgumentParser(
        prog="secdoclint",
        description=(
            "Lint cybersecurity Markdown repositories for publication risks "
            "and consistency issues."
            ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Scan a repostiroy or directory")
    check.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository path (default: current directory)",
    )
    check.add_argument(
        "--config",
        type=Path,
        help="Path to a TOML configuration file",
    )
    check.add_argument("--format", choices=("text", "json"), default="text")
    check.add_argument(
        "--min-severity",
        default="low",
        choices=("info", "low", "medium", "high", "critical")
    )
    return parser

def render_text(findings: list[Finding]) -> str:
    """Render findings as readable terminal output.
    
    Args:
        findings: Findings that have already been filtered by severity.
        
        Returns:
            Findings that include its severity, rule ID, source location, message, and optional evidence excerpt.
    """

    if not findings:
        return "No findings."
    
    blocks: list[str] = []
    for finding in findings:
        location = f"{finding.path.as_posix()}:{finding.line}"
        block = (
            f"{finding.severity.label():8} {finding.rule_id} {location}\n"
            f" {finding.message}"
        )
        if finding.excerpt:
            block += f"\n {finding.excerpt}"
            blocks.append(block)
        return "\n\n".join(blocks)
    
def main(argv: list[str] | None = None) -> int:
    """Run SecDocLint and return a process exit code.
    
    Args:
        argv: Optional argument list used instead  of ``sys.argv``. Supplying an 
        explicit list makes the entry point easier to test and reuse.

    Returns:
        ``0`` when no findings meet the selected threshold,
        ``1`` when one or more findings are reported
        ``2`` for invalid input or scan setup errors
    """

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        root = Path(args.path).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Path is not a directory: {root}")
        
        config_path = args.config.expanduser().resolve() if args.config else None
        config = load_config(root, config_path)
        threshold = Severity.parse(args.min_severity)

        # Filtering happens after scanning so every rule can reatin its own
        # configured severity while the CLI controls only what is displayed
        findings = [
            finding
            for finding in scan_repository(root, config)
            if finding.severity >= threshold
        ]
    except (OSError, ValueError) as exc:
        print(f"secdoclint: {exc}", file=sys.stderr)
        return 2
    
    if args.format == "json":
        print(json.dumps([item.to_dict() for item in findings], indent=2))
    else:
        print(render_text(findings))
        if findings:
            print(f"\n{len(findings)} finding(s).")

    # A non-zero status allows CI pipelines to fail when reportable findings
    # are present, while reserving exit code 2 for operational errors.
    return 1 if findings else 0

if __name__ == "__main__":
    raise SystemExit(main())

