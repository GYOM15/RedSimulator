"""Payload effectiveness tracking.

Records which payloads succeed or fail against which technologies and
persists the data to ``data/payload_stats.json`` for cross-session learning.
The feedback loop lets the smart selector boost payloads that have historically
performed well against specific technology stacks.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from src.infra.logging import get_logger

from .payload_models import PayloadStats

logger = get_logger(__name__)


def _payload_hash(text: str) -> str:
    """Produce a stable, short hash for a payload string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class FeedbackTracker:
    """Tracks and persists payload effectiveness across sessions.

    Thread-safe. Automatically loads existing stats on instantiation and
    saves after each recorded result.
    """

    def __init__(self, stats_path: str | Path | None = None) -> None:
        if stats_path is None:
            project_root = Path(__file__).resolve().parent.parent.parent
            stats_path = project_root / "data" / "payload_stats.json"
        self._path = Path(stats_path)
        self._stats: dict[str, PayloadStats] = {}
        self._lock = threading.Lock()
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, payload_text: str, technology: str, success: bool) -> None:
        """Record an execution result for a payload against a technology.

        Args:
            payload_text: The payload that was used.
            technology:   The target technology (e.g. "sqlite", "mysql").
            success:      Whether the payload triggered a vulnerability.
        """
        h = _payload_hash(payload_text)
        tech = technology.lower()

        with self._lock:
            if h not in self._stats:
                self._stats[h] = PayloadStats(payload_hash=h)

            stat = self._stats[h]
            stat.total_uses += 1
            if success:
                stat.successes += 1

            if tech not in stat.by_technology:
                stat.by_technology[tech] = {"uses": 0, "successes": 0}

            stat.by_technology[tech]["uses"] += 1
            if success:
                stat.by_technology[tech]["successes"] += 1

            self._save()

    def get_boost(self, payload_text: str, technology: str) -> float:
        """Get an effectiveness boost score for ranking.

        Returns a value between 0.0 and 1.0 that reflects historical
        success of this payload against the specified technology.
        Falls back to the overall success rate if no technology-specific
        data is available. Returns 0.0 for unknown payloads.
        """
        h = _payload_hash(payload_text)
        with self._lock:
            stat = self._stats.get(h)

        if stat is None:
            return 0.0

        # Prefer technology-specific rate if enough data
        tech = technology.lower()
        tech_data = stat.by_technology.get(tech)
        if tech_data and tech_data.get("uses", 0) >= 3:
            return tech_data["successes"] / tech_data["uses"]

        # Fall back to overall rate
        return stat.success_rate

    def top_payloads(self, attack_type: str, technology: str, n: int = 10) -> list[str]:
        """Get the payload hashes with the highest success rate for a tech.

        Note: returns *hashes*, not full payload texts, because this tracker
        only stores hashes. The caller should use the hash to look up the
        original payload in the database.

        Args:
            attack_type: Not currently used for filtering (reserved for future).
            technology:  Technology to rank by.
            n:           Maximum results to return.
        """
        tech = technology.lower()
        scored: list[tuple[str, float]] = []

        with self._lock:
            for h, stat in self._stats.items():
                tech_data = stat.by_technology.get(tech)
                if tech_data and tech_data.get("uses", 0) > 0:
                    rate = tech_data["successes"] / tech_data["uses"]
                    scored.append((h, rate))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [h for h, _ in scored[:n]]

    def get_stats_summary(self) -> dict:
        """Return a summary of tracking statistics."""
        with self._lock:
            total_payloads = len(self._stats)
            total_uses = sum(s.total_uses for s in self._stats.values())
            total_successes = sum(s.successes for s in self._stats.values())
            technologies: set[str] = set()
            for s in self._stats.values():
                technologies.update(s.by_technology.keys())

        return {
            "tracked_payloads": total_payloads,
            "total_uses": total_uses,
            "total_successes": total_successes,
            "overall_success_rate": total_successes / total_uses if total_uses > 0 else 0.0,
            "technologies_seen": sorted(technologies),
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Load stats from the JSON file on disk."""
        if not self._path.exists():
            logger.debug("No payload stats file found at %s, starting fresh", self._path)
            return

        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            for h, data in raw.items():
                self._stats[h] = PayloadStats(
                    payload_hash=h,
                    total_uses=data.get("total_uses", 0),
                    successes=data.get("successes", 0),
                    by_technology=data.get("by_technology", {}),
                )
            logger.info("Loaded %d payload stats from %s", len(self._stats), self._path)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load payload stats from %s: %s", self._path, e)

    def _save(self) -> None:
        """Persist stats to the JSON file on disk."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            for h, stat in self._stats.items():
                data[h] = {
                    "total_uses": stat.total_uses,
                    "successes": stat.successes,
                    "by_technology": stat.by_technology,
                }
            self._path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as e:
            logger.error("Failed to save payload stats to %s: %s", self._path, e)


# Module-level singleton
feedback_tracker = FeedbackTracker()
