"""Data models for multi-target campaign orchestration.

All models are plain dataclasses to stay lightweight and independent
of Pydantic (the pipeline models use Pydantic, but campaign-level
bookkeeping does not need validation beyond what Python typing provides).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class TargetConfig:
    """Configuration for a single scan target within a campaign."""

    url: str
    name: str = ""  # Human-friendly label
    auth_type: str = "none"
    auth_credentials: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = self.url


@dataclass
class CampaignConfig:
    """Top-level configuration for a multi-target campaign."""

    name: str
    targets: list[TargetConfig]
    parallel: bool = False  # Run targets in parallel or sequential
    max_parallel: int = 3
    use_fixtures: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


@dataclass
class TargetResult:
    """Outcome of running the pipeline against a single target."""

    target: TargetConfig
    scan_result: dict | None = None
    attack_plan: dict | None = None
    attack_result: dict | None = None
    report: str = ""
    status: str = "pending"  # pending, running, completed, failed
    error: str = ""
    duration_ms: float = 0.0


@dataclass
class CampaignResult:
    """Aggregated outcome of a multi-target campaign."""

    config: CampaignConfig
    results: list[TargetResult] = field(default_factory=list)
    status: str = "pending"

    @property
    def summary(self) -> dict:
        """Compute a high-level summary across all targets."""
        completed = [r for r in self.results if r.status == "completed"]
        failed = [r for r in self.results if r.status == "failed"]
        total_vulns = sum(
            r.attack_result.get("total_attempts", 0) for r in completed if r.attack_result
        )
        successful_attacks = sum(
            r.attack_result.get("successful_attacks", 0) for r in completed if r.attack_result
        )
        return {
            "total_targets": len(self.results),
            "completed": len(completed),
            "failed": len(failed),
            "total_vulnerabilities": total_vulns,
            "successful_attacks": successful_attacks,
        }
