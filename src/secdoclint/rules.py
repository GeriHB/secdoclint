"""Individual lint rules for repository text and Markdown content.

The functions in this module do not traverse repositories themselves. Each
scanner receives the current path and file text, applies one family of checks,
and returns zero or more :class:`~secdoclint.models.Finding` objects.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path
from typing import Iterable

from .config import Config
from .models import Finding, Severity


@dataclass(frozen=True, slots=True)
class PatternRule:
    """Definition of a regular-expression-based publication-safety rule.

    Attributes:
        rule_id: Stable identifier shown in output and configuration.
        severity: Default severity before repository overrides are applied.
        pattern: Compiled expression searched against each source line.
        message: Explanation returned when the pattern matches.
    """

    rule_id: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str


# These rules intentionally operate line by line. That keeps finding locations
# precise and prevents excerpts from exposing more document content than needed.
PATTERN_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "DOC-SECRET-001",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "Private-key material appears to be present.",
    ),
    PatternRule(
        "DOC-SECRET-002",
        Severity.HIGH,
        re.compile(
            r"\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9+/._=-]{8,}",
            re.I,
        ),
        "Authorization header may expose reusable authentication material.",
    ),
    PatternRule(
        "DOC-SECRET-003",
        Severity.HIGH,
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{10,}\b"
        ),
        "JWT-like token appears to be present.",
    ),
    PatternRule(
        "DOC-SECRET-004",
        Severity.CRITICAL,
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
        "GitHub token-like value appears to be present.",
    ),
    PatternRule(
        "DOC-SECRET-005",
        Severity.HIGH,
        re.compile(r"\b(?:HTB|TUCTF|THM|FLAG|flag)\{[^}\n]{3,}\}"),
        "Lab or CTF flag appears to be present.",
    ),
    PatternRule(
        "DOC-SECRET-006",
        Severity.MEDIUM,
        re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])"),
        "Full 32-character hexadecimal value may be credential or key material.",
    ),
    PatternRule(
        "DOC-SECRET-007",
        Severity.HIGH,
        re.compile(r"\bdoI[A-Za-z0-9+/=]{120,}\b"),
        "Large Kerberos-ticket-like Base64 value appears to be present.",
    ),
)

# File types that commonly contain credentials, captures, secrets, or host
# artefacts and are therefore risky to publish in a documentation repository.
SENSITIVE_SUFFIXES = {
    ".kirbi",
    ".ccache",
    ".ovpn",
    ".pfx",
    ".p12",
    ".pcap",
    ".pcapng",
    ".dmp",
    ".dit",
    ".sam",
    ".system",
    ".security",
    ".pem",
    ".key",
}

# Generic alt text makes screenshots inaccessible and fails to describe what
# a piece of evidence demonstrates in a technical report.
GENERIC_ALT = re.compile(
    r"!\[(?:alt text|image|screenshot|proof|evidence|img|picture)?\]\(([^)]+)\)",
    re.I,
)
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
CONFIRMED_WORDS = re.compile(
    r"\b(?:validated|confirmed|demonstrated|successful|succeeded)\b",
    re.I,
)
UNCONFIRMED_WORDS = re.compile(
    r"\b(?:not independently (?:tested|validated|executed)|"
    r"requires revalidation|not validated|not tested)\b",
    re.I,
)


def apply_severity_override(
    config: Config,
    rule_id: str,
    default: Severity,
) -> Severity:
    """Return a configured rule severity or its built-in default.

    Args:
        config: Active repository configuration.
        rule_id: Rule whose severity may have been overridden.
        default: Severity defined by the rule implementation.
    """

    return config.rule_overrides.get(rule_id, default)


def scan_pattern_rules(path: Path, text: str, config: Config) -> list[Finding]:
    """Scan each line for token, credential, flag, and key-like patterns.

    Excerpts are capped at 160 characters to keep terminal and JSON output
    readable and to avoid reproducing excessive sensitive content.
    """

    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in PATTERN_RULES:
            if rule.pattern.search(line):
                excerpt = line.strip()
                if len(excerpt) > 160:
                    excerpt = excerpt[:157] + "..."
                findings.append(
                    Finding(
                        rule.rule_id,
                        apply_severity_override(config, rule.rule_id, rule.severity),
                        path,
                        line_number,
                        rule.message,
                        excerpt,
                    )
                )
    return findings


def scan_generic_alt_text(path: Path, text: str, config: Config) -> list[Finding]:
    """Report Markdown images whose alt text is empty or generic."""

    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if GENERIC_ALT.search(line):
            findings.append(
                Finding(
                    "DOC-MARKDOWN-002",
                    apply_severity_override(
                        config,
                        "DOC-MARKDOWN-002",
                        Severity.LOW,
                    ),
                    path,
                    line_number,
                    "Generic image alt text does not explain what the evidence proves.",
                    line.strip(),
                )
            )
    return findings


def scan_broken_links(
    root: Path,
    path: Path,
    text: str,
    config: Config,
) -> list[Finding]:
    """Find missing local targets in Markdown links and image references.

    Args:
        root: Absolute repository root used as the allowed path boundary.
        path: Absolute path of the Markdown file being inspected.
        text: Markdown source text.
        config: Active repository configuration.

    Returns:
        Findings for local links whose resolved targets do not exist.

    Notes:
        External URLs, email links, in-page anchors, data URIs, and paths that
        resolve outside the repository are deliberately skipped.
    """

    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in MARKDOWN_LINK.finditer(line):
            target = match.group(1).strip()

            # A fragment identifies a heading within a file. Only the file
            # path is needed for this existence check.
            target = target.split("#", 1)[0].strip()

            if not target or target.startswith(
                ("http://", "https://", "mailto:", "#", "data:")
            ):
                continue

            # Markdown permits angle brackets around destinations that contain
            # spaces; remove them before resolving the filesystem path.
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]

            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(root.resolve())
            except ValueError:
                # Do not inspect or report paths outside the scanned repository.
                continue

            if not resolved.exists():
                findings.append(
                    Finding(
                        "DOC-MARKDOWN-001",
                        apply_severity_override(
                            config,
                            "DOC-MARKDOWN-001",
                            Severity.MEDIUM,
                        ),
                        path,
                        line_number,
                        f"Relative Markdown link points to a missing path: {target}",
                        line.strip(),
                    )
                )
    return findings


def scan_code_blocks(path: Path, text: str, config: Config) -> list[Finding]:
    """Report fenced code blocks that exceed the configured line limit.

    Both backtick and tilde fences are supported. The scanner records the
    opening-fence line so the finding points to the start of the large block.
    """

    findings: list[Finding] = []
    in_block = False
    start_line = 0
    count = 0
    fence = ""

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()

        if not in_block and (
            stripped.startswith("```") or stripped.startswith("~~~")
        ):
            in_block = True
            start_line = line_number
            count = 0
            fence = stripped[:3]
            continue

        if in_block and stripped.startswith(fence):
            if count > config.max_code_block_lines:
                findings.append(
                    Finding(
                        "DOC-CODE-001",
                        apply_severity_override(
                            config,
                            "DOC-CODE-001",
                            Severity.LOW,
                        ),
                        path,
                        start_line,
                        (
                            f"Fenced code block contains {count} lines; "
                            "consider reducing it to essential evidence."
                        ),
                    )
                )
            in_block = False
            continue

        if in_block:
            count += 1

    return findings


def iter_sections(text: str) -> Iterable[tuple[int, str, str]]:
    """Yield Markdown sections as ``(start_line, title, body)`` tuples.

    Text before the first heading is represented by a synthetic ``<document>``
    section. Heading levels are treated equally because the consistency rule
    only needs a local body of text, not a full Markdown hierarchy.
    """

    current_title = "<document>"
    current_line = 1
    body: list[str] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        if re.match(r"^#{1,6}\s+", line):
            yield current_line, current_title, "\n".join(body)
            current_title = re.sub(r"^#{1,6}\s+", "", line).strip()
            current_line = line_number
            body = []
        else:
            body.append(line)

    # Emit the final section because no later heading exists to trigger it.
    yield current_line, current_title, "\n".join(body)


def scan_claim_conflicts(path: Path, text: str, config: Config) -> list[Finding]:
    """Detect sections that describe the same result as tested and untested.

    This heuristic helps catch reporting contradictions such as stating that an
    attack path was validated and later saying it was not independently tested.
    """

    findings: list[Finding] = []
    for start_line, title, body in iter_sections(text):
        if CONFIRMED_WORDS.search(body) and UNCONFIRMED_WORDS.search(body):
            findings.append(
                Finding(
                    "DOC-CONSISTENCY-001",
                    apply_severity_override(
                        config,
                        "DOC-CONSISTENCY-001",
                        Severity.MEDIUM,
                    ),
                    path,
                    start_line,
                    (
                        f"Section '{title}' contains both confirmed-validation "
                        "language and a statement that the technique was not "
                        "independently tested."
                    ),
                )
            )
    return findings
