# Shared data models used throughout SecDocLint

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

class Severity(IntEnum):
    """Ordered severity levels assigned to findings.
    
    Integer ordering allows direct comparisons such as 
    ``finding.severity >= threshold`` without a separate lookup table.
    """

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Convert a case-insensitive severity name into an enum member.
        
        Args:
            value: Severity text such as ``"medium"`` or ``"HIGH"``.
            
            Returns:
                The corresponding :class: `Severity` member.
                
            Raises:
                ValueError: If ``value`` is not one of the supported levels.
        """

        normalized = value.strip().upper()
        try:
            return cls[normalized]
        except KeyError as exc:
            allowed = ", ".join(item.name.lower() for item in cls)
            raise ValueError(
                f"Unknown severity '{value}'. Excpected one of: {allowed}"
            ) from exc
        
    def label(self) -> str:
        """Return the uppercase label used in text report."""

        return self.name
    
@dataclass(frozen=True, slots=True)
class Finding:
    """A single issue reported by a SecDocLint rule.
    
    Attributes:
        rule_id: Stable identifier for the rule that produced the finding
        severity: Importance level used for sorting and filtering
        path: Repository-relative path to the affected file
        line: Line number where the issue was found
        message: Explanation of the issue
        excerpt: Short piece of source text that supports the result
    """

    rule_id: str
    severity: Severity
    path: Path
    line: int
    message: str
    excerpt: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Convert the finding into JSON-serializable primitive values."""

        return{
            "rule_id": self.rule_id,
            "severity": self.severity.name.lower(),
            "path": self.path.as_posix(),
            "line": self.line,
            "message": self.message,
            "excerpt": self.excerpt,
        }