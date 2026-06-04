"""Detection rate tracking for regression testing.

Persists run results to a JSON file so that detection rates can be
compared across runs.  The :class:`DetectionTracker` is intentionally
simple (flat JSON, no database) to keep the infrastructure lightweight.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class RunResult:
    """Snapshot of a single battle-test run."""

    timestamp: str
    target: str
    rules_fired: int
    vectors_found: int
    attack_types: list[str]
    severities: dict[str, int]


class DetectionTracker:
    """Tracks detection results over time.

    Results are appended to a flat JSON array at *history_path*.
    """

    def __init__(self, history_path: str = "data/regression/history.json") -> None:
        self.path = Path(history_path)
        self.history: list[dict] = self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, result: RunResult) -> None:
        """Append a new run result to the history file."""
        self.history.append(asdict(result))
        self._save()

    def get_latest(self, target: str) -> RunResult | None:
        """Return the most recent result for *target*, or ``None``."""
        for entry in reversed(self.history):
            if entry.get("target") == target:
                return RunResult(**entry)
        return None

    def check_regression(
        self,
        current: RunResult,
        threshold: float = 0.9,
    ) -> tuple[bool, str]:
        """Check whether *current* detection rate regressed vs the last run.

        A regression is declared when the current vector count falls below
        *threshold* times the previous run's vector count.

        Returns:
            ``(passed, explanation)`` where *passed* is ``True`` when no
            regression was detected.
        """
        previous = self.get_latest(current.target)
        if previous is None:
            return True, "No previous run to compare against."

        min_vectors = int(previous.vectors_found * threshold)
        if current.vectors_found < min_vectors:
            return False, (
                f"Regression detected for {current.target}: "
                f"vectors dropped from {previous.vectors_found} to "
                f"{current.vectors_found} (threshold={threshold})."
            )

        min_rules = int(previous.rules_fired * threshold)
        if current.rules_fired < min_rules:
            return False, (
                f"Regression detected for {current.target}: "
                f"rules_fired dropped from {previous.rules_fired} to "
                f"{current.rules_fired} (threshold={threshold})."
            )

        return True, (
            f"No regression for {current.target}: "
            f"vectors {previous.vectors_found} -> {current.vectors_found}, "
            f"rules {previous.rules_fired} -> {current.rules_fired}."
        )

    # ------------------------------------------------------------------
    # Convenience factory
    # ------------------------------------------------------------------

    @staticmethod
    def make_result(
        target: str,
        rules_fired: int,
        vectors_found: int,
        attack_types: list[str],
        severities: dict[str, int],
    ) -> RunResult:
        """Create a :class:`RunResult` with the current UTC timestamp."""
        return RunResult(
            timestamp=datetime.now(UTC).isoformat(),
            target=target,
            rules_fired=rules_fired,
            vectors_found=vectors_found,
            attack_types=attack_types,
            severities=severities,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> list[dict]:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.history, indent=2, ensure_ascii=False))
