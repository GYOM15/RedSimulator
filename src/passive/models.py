"""Data models for passive scanning findings.

Passive scanning analyzes HTTP responses without sending new requests.
These models capture the results of that analysis.
"""

from dataclasses import dataclass, field
from enum import StrEnum


class FindingSeverity(StrEnum):
    """Severity levels for passive scan findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class PassiveFinding:
    """A single finding from a passive check.

    Attributes:
        check_name: Machine-readable check identifier (e.g. "missing_hsts").
        severity: Severity level of the finding.
        title: Human-readable title.
        description: Detailed description of what was found.
        url: The URL/endpoint where the finding was detected.
        evidence: The specific header/value/content that triggered the finding.
        cwe_id: CWE reference (e.g. "CWE-614").
        remediation: How to fix the issue.
    """

    check_name: str
    severity: FindingSeverity
    title: str
    description: str
    url: str
    evidence: str = ""
    cwe_id: str = ""
    remediation: str = ""


@dataclass
class PassiveReport:
    """Aggregated report of all passive scan findings.

    Attributes:
        findings: List of all findings from all checks.
    """

    findings: list[PassiveFinding] = field(default_factory=list)

    @property
    def by_severity(self) -> dict[str, int]:
        """Count findings grouped by severity level."""
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def by_check(self) -> dict[str, int]:
        """Count findings grouped by check name."""
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.check_name] = counts.get(f.check_name, 0) + 1
        return counts
