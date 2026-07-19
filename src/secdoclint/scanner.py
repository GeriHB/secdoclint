"""Repo traversal and rule orchestration for SecDocLint."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

from .config import Config
from .models import Finding, Severity
from .rules import (
    SENSITIVE_SUFFIXES,
    apply_severity_override,
    scan_broken_links,
    scan_claim_conflicts,
    scan_code_blocks,
    scan_generic_alt_text,
    scan_pattern_rules,
)

# Only text-like files are decoded and inspected for inline patterns.
# Binary files may still be reported separately when their suffix is sensitive
TEXT_SUFFIXES = {
    ".md",
    ".markdown",
    ".txt",
    ".rst",
    ".py",
    ".sh",
    ".ps1",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".conf",
    ".xml",
    ".html",
    ".http",
}

def is_excluded(root: Path, path: Path, patterns: list[str]) -> bool:
    """Return whether a path matches any repo-relative exclusion glob.
    
    Both the plain relative path and a slash-suffixed form are checked so that
    patterns written for directory trees also match consistently.
    """

    relative = path.relative_to(root).as_posix()
    return any(
        fnmatch(relative, pattern) or fnmatch(f"{relative}/", pattern)
        for pattern in patterns
    )

def scan_required_files(root: Path, config: Config) -> list[Finding]:
    """Check that every configured group has at least one existing file.
    
    Each entry in ``Config.required_any`` is an OR group. For example, a group
    containing ``README.md`` and ``README.rst`` is satisfied when either file exists."""

    findings: list[Finding] = []
    for candidates in config.required_any:
        if not any((root / candidate).exists() for candidate in candidates):
            readable = " or ".join(candidates)
            findings.append(
                Finding(
                    "REPO-STRUCTURE-001",
                    apply_severity_override(
                        config,
                        "REPO-STRUCTURE-001",
                        Severity.LOW,
                    ),
                    Path("."),
                    1,
                    f"Repository is missing an expected file: {readable}",
                )
            )
    return findings

def scan_repository(root: Path, config: Config) -> list[Finding]:
    """Scan a repository and return findings in deterministic priority order.

    Args:
        root: Directory treated as the repository boundary.
        config: Active scanner configuration.

    Returns:
        Findings sorted by descending severity, then path, line, and rule ID.

    Notes:
        Sensitive file extensions are reported even when the file is binary.
        Text-content rules are only applied to suffixes listed in
        :data:`TEXT_SUFFIXES`. Markdown-specific rules are restricted to
        ``.md`` and ``.markdown`` files.
    """

    root = root.resolve()
    findings = scan_required_files(root, config)

    for path in sorted(root.rglob("*")):
        if not path.is_file() or is_excluded(root, path, config.exclude_globs):
            continue

        relative = path.relative_to(root)
        suffix = path.suffix.lower()

        if suffix in SENSITIVE_SUFFIXES:
            findings.append(
                Finding(
                    "FILE-SENSITIVE-001",
                    apply_severity_override(
                        config,
                        "FILE-SENSITIVE-001",
                        Severity.HIGH,
                    ),
                    relative,
                    1,
                    f"Sensitive file type is tracked: {suffix}",
                )
            )

        if suffix not in TEXT_SUFFIXES:
            continue

        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # A file with a text-like suffix may still contain binary data.
            # Skipping it avoids unreliable partial decoding and false results.
            continue
        except OSError as exc:
            findings.append(
                Finding(
                    "FILE-READ-001",
                    Severity.INFO,
                    relative,
                    1,
                    f"Could not read file: {exc}",
                )
            )
            continue

        # Publication-safety patterns apply to every supported text format.
        findings.extend(scan_pattern_rules(relative, text, config))

        if suffix in {".md", ".markdown"}:
            findings.extend(scan_generic_alt_text(relative, text, config))

            # Link resolution requires the absolute source path, while findings
            # should expose only repository-relative paths in their output.
            broken = scan_broken_links(root, path, text, config)
            findings.extend(
                Finding(
                    item.rule_id,
                    item.severity,
                    relative,
                    item.line,
                    item.message,
                    item.excerpt,
                )
                for item in broken
            )

            findings.extend(scan_code_blocks(relative, text, config))
            findings.extend(scan_claim_conflicts(relative, text, config))

    return sorted(
        findings,
        key=lambda item: (
            -int(item.severity),
            item.path.as_posix(),
            item.line,
            item.rule_id,
        ),
    )
