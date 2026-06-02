"""Centralized payload database.

Loads categorized payloads from data/payloads/{attack_type}/*.txt files.
Lazy-loaded per category on first access. Thread-safe singleton.
"""

from __future__ import annotations

import threading
from pathlib import Path

from src.infra.config import settings
from src.infra.logging import get_logger

logger = get_logger(__name__)


class PayloadDatabase:
    """Singleton payload database with lazy category loading."""

    _instance: PayloadDatabase | None = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> PayloadDatabase:
        if cls._instance is None:
            with cls._lock:
                # Double-checked locking
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._cache: dict[str, dict[str, list[str]]] = {}
                    instance._cache_lock = threading.Lock()
                    # Resolve relative to project root if needed
                    raw_path = Path(settings.payload_db_path)
                    if raw_path.is_absolute():
                        instance._base_path = raw_path
                    else:
                        # Resolve relative to the project root (3 levels up from this file)
                        project_root = Path(__file__).resolve().parent.parent.parent
                        instance._base_path = project_root / raw_path
                    cls._instance = instance
        return cls._instance

    def _load_category(self, attack_type: str, category: str) -> list[str]:
        """Load payloads from a single .txt file.

        Lines starting with '#' are treated as comments and skipped.
        Empty lines are skipped.
        """
        file_path = self._base_path / attack_type / f"{category}.txt"
        if not file_path.exists():
            logger.warning("Payload file not found: %s", file_path)
            return []

        payloads: list[str] = []
        try:
            with open(file_path, encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        payloads.append(stripped)
        except OSError as e:
            logger.error("Failed to read payload file %s: %s", file_path, e)
            return []

        logger.info(
            "Loaded %d payloads from %s/%s",
            len(payloads),
            attack_type,
            category,
        )
        return payloads

    def _ensure_loaded(self, attack_type: str) -> dict[str, list[str]]:
        """Ensure all categories for an attack type are loaded into the cache."""
        if attack_type in self._cache:
            return self._cache[attack_type]

        with self._cache_lock:
            # Double-checked locking
            if attack_type in self._cache:
                return self._cache[attack_type]

            categories: dict[str, list[str]] = {}
            type_dir = self._base_path / attack_type

            if type_dir.is_dir():
                for txt_file in sorted(type_dir.glob("*.txt")):
                    cat_name = txt_file.stem
                    categories[cat_name] = self._load_category(attack_type, cat_name)
            else:
                logger.debug(
                    "No payload directory for attack type: %s (looked in %s)",
                    attack_type,
                    type_dir,
                )

            self._cache[attack_type] = categories
            return categories

    def get(
        self,
        attack_type: str,
        category: str | None = None,
        limit: int | None = None,
    ) -> list[str]:
        """Get payloads for an attack type, optionally filtered by category.

        Args:
            attack_type: e.g. "sqli", "xss", "idor"
            category: e.g. "auth_bypass", "union_based". None = all categories.
            limit: Max payloads to return. None = all.

        Returns:
            List of payload strings.
        """
        categories = self._ensure_loaded(attack_type)

        if category is not None:
            payloads = list(categories.get(category, []))
        else:
            # Merge all categories
            payloads = []
            for cat_payloads in categories.values():
                payloads.extend(cat_payloads)

        if limit is not None:
            payloads = payloads[:limit]

        return payloads

    def categories(self, attack_type: str) -> list[str]:
        """List available categories for an attack type."""
        categories = self._ensure_loaded(attack_type)
        return sorted(categories.keys())

    def stats(self) -> dict[str, int]:
        """Return count of payloads per attack type.

        Scans all attack type directories under the base path and
        counts total payloads for each.
        """
        result: dict[str, int] = {}

        if not self._base_path.is_dir():
            logger.warning("Payload database path does not exist: %s", self._base_path)
            return result

        for type_dir in sorted(self._base_path.iterdir()):
            if type_dir.is_dir():
                attack_type = type_dir.name
                categories = self._ensure_loaded(attack_type)
                total = sum(len(payloads) for payloads in categories.values())
                if total > 0:
                    result[attack_type] = total

        return result


# Module-level convenience
payload_db = PayloadDatabase()
