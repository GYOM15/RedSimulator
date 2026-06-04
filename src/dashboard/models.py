"""Data models for dashboard historical tracking.

These dataclasses represent scan snapshots and trend analysis data
stored in the SQLite dashboard database.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanSnapshot:
    """A historical snapshot of a scan run.

    Captures aggregate metrics from a single pipeline execution
    so they can be compared over time.
    """

    id: str  # UUID
    timestamp: str  # ISO 8601
    target: str  # Target URL
    total_vectors: int  # Number of attack vectors identified
    total_attempts: int  # Number of attack attempts executed
    successful_attacks: int  # Number of successful exploitations
    severity_counts: dict[str, int]  # e.g. {"CRITICAL": 2, "HIGH": 3}
    attack_types: list[str]  # e.g. ["sqli", "xss", "idor"]
    rules_fired: int  # Number of expert rules that fired
    cvss_scores: list[dict] = field(  # [{vector_id, score, severity, vector_string}]
        default_factory=list,
    )
    risk_score: int = 0  # 0-100
    duration_ms: float = 0.0  # Pipeline execution time


@dataclass
class TrendData:
    """Trend analysis for a target over time.

    Aggregates multiple ScanSnapshot instances for a single target
    to enable time-series visualization of risk and vulnerability counts.
    """

    target: str
    snapshots: list[ScanSnapshot] = field(default_factory=list)

    @property
    def risk_trend(self) -> list[dict]:
        """Risk score over time.

        Returns a list of {date, score} dicts sorted chronologically.
        """
        return [{"date": s.timestamp, "score": s.risk_score} for s in self.snapshots]

    @property
    def vuln_trend(self) -> list[dict]:
        """Vulnerability count over time.

        Returns a list of {date, total} dicts sorted chronologically.
        """
        return [{"date": s.timestamp, "total": s.total_vectors} for s in self.snapshots]

    @property
    def success_rate_trend(self) -> list[dict]:
        """Exploitation success rate over time.

        Returns a list of {date, rate} dicts where rate is 0.0-1.0.
        """
        result = []
        for s in self.snapshots:
            rate = s.successful_attacks / s.total_attempts if s.total_attempts > 0 else 0.0
            result.append({"date": s.timestamp, "rate": round(rate, 4)})
        return result

    @property
    def severity_trend(self) -> list[dict]:
        """Severity distribution over time.

        Returns a list of {date, CRITICAL, HIGH, MEDIUM, LOW} dicts.
        """
        result = []
        for s in self.snapshots:
            entry: dict = {"date": s.timestamp}
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                entry[sev] = s.severity_counts.get(sev, 0)
            result.append(entry)
        return result
