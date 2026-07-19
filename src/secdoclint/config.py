"""Configuration model and TOML loader for SecDocLint.

Repositories may provide a ``.secdoclint.toml`` file to change exculded paths, code-block limits, expected files, and per-rule severity levels.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import tomllib

from .models import Severity

@dataclass(slots=True)
class Config:
    """Runtime settings used by repository and rule scanners.
    
    Attributes:
        exclude_globs: Repository-relative glob patterns that are ignored.
        max_code_block_lines: Maximum preferred size of a fenced code block.
        required_any: Groups of alternative files. At least one file from
            each group must exist, for example ``README.md`` in the ifrst group
            and ``DISCLAIMER.md`` in the second.
        rule_overrides: Optional replacement severity for individual rule IDs.
    """

    exclude_globs: list[str] = field(
        default_factory=lambda: [
            ".git/**",
            ".venv/**",
            "dist/**",
            "build/**",
            "**/__pycache__/**",
        ]
    )
    max_code_block_lines: int = 100
    required_any: list[list[str]] = field(
        default_factory=lambda: [["README.md"], ["DISCLAIMER.md"]]
    )
    rule_overrides: dict[str, Severity] = field(default_factory=dict)

def load_config(root: Path, explicit: Path | None = None) -> Config:
    """Load SecDocLint configuration for a repository.
    
    Args:
        root: Root directory of the repository being scanned.
        explicit: Optional path supplied with ``--config``. When omitted, the
            loader looks for ``.secdoclint.toml`` in ``root``.
            
        Returns:
            A configuration object containing defaults plus any TOML overrides.
            
        Raises:
            OSError: If an existing configuration file cannot be opened.
            tomlllib.TOMLDecodeError: If the TOML content is malformed.
            ValueError: If a configured value is invalid, such as a non-positive code-block limit or an unknown severity name.
    """

    config = Config()
    path = explicit or (root / ".secdoclint.toml")

    if not path.exists():
        return config
    
    with path.open("rb") as handle:
        raw = tomllib.load(handle)

    if "exclude_globs" in raw:
        config.exclude_globs = [str(item) for item in raw["exclude_globs"]]

    if "max_code_block_lines" in raw:
        value = int(raw["max_code_block_lines"])
        if value < 1:
            raise ValueError("max_code_block_lines must be greater than zero")
        config.max_code_block_lines = value

    if "required_any" in raw:
        config.required_any = [
            [str(candidate) for candidate in group]
            for group in raw["required_any"]
        ]

    # Rule IDs remain strings so new rules can be configured without changing
    # the configuration schema. Severity.parse validates each supplied value

    for rule_id, severity in raw.get("rule_overrides", {}).items():
        config.rule_overrides[str(rule_id)] = Severity.parse(str(severity))

    return config