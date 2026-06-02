"""Intelligent payload database with contextual metadata.

Loads annotated payloads from ``data/payloads/{attack_type}/*.jsonl`` files.
Each line is a JSON object with payload text plus intelligence metadata
(target databases, injection contexts, WAF bypass capabilities, etc.).

Falls back to ``.txt`` files (legacy format) with default metadata for
backward compatibility.

The smart selector (``select_for_target``) infers database engine, WAF
presence, and injection context from scan results, then ranks payloads
by relevance and historical effectiveness.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from src.infra.config import settings
from src.infra.logging import get_logger

from .feedback import feedback_tracker
from .payload_models import IntelPayload

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# WAF / database detection helpers
# ---------------------------------------------------------------------------

_WAF_HEADER_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    # WAF name -> list of (header_name_lower, substring_in_value)
    "cloudflare": [
        ("server", "cloudflare"),
        ("cf-ray", ""),
    ],
    "aws_waf": [
        ("server", "awselb"),
        ("x-amzn-requestid", ""),
        ("x-amz-apigw-id", ""),
    ],
    "modsecurity": [
        ("server", "modsecurity"),
        ("server", "mod_security"),
    ],
    "akamai": [
        ("x-akamai-transformed", ""),
        ("server", "akamaighost"),
    ],
    "imperva": [
        ("x-cdn", "imperva"),
        ("x-iinfo", ""),
    ],
    "generic": [
        ("x-waf", ""),
        ("x-firewall", ""),
        ("x-sucuri-id", ""),
    ],
}

_DATABASE_KEYWORDS: dict[str, list[str]] = {
    # Normalized DB name -> keywords to match (case-insensitive) in technologies
    "sqlite": ["sqlite"],
    "mysql": ["mysql", "mariadb"],
    "postgresql": ["postgresql", "postgres", "pgsql"],
    "mssql": ["mssql", "sql server", "microsoft sql"],
    "oracle": ["oracle"],
    "nosql": ["mongodb", "mongo", "couchdb"],
}


def _detect_waf(headers: dict | None) -> str | None:
    """Detect WAF from HTTP response headers.

    Inspects well-known header signatures for popular WAFs.
    Returns the WAF name or None if no WAF is detected.
    """
    if not headers:
        return None

    # Normalize header names to lowercase
    lower_headers: dict[str, str] = {}
    for k, v in headers.items():
        lower_headers[k.lower()] = str(v).lower()

    for waf_name, signatures in _WAF_HEADER_SIGNATURES.items():
        for header_name, value_substring in signatures:
            header_value = lower_headers.get(header_name)
            if header_value is not None and (
                not value_substring or value_substring in header_value
            ):
                logger.debug("WAF detected: %s (via header %s)", waf_name, header_name)
                return waf_name

    return None


def _detect_database(technologies: list[str]) -> list[str]:
    """Infer database engine from detected technologies.

    Matches technology strings against known database keywords.
    Returns a list of detected database names, or ``["any"]`` if
    none are detected.
    """
    if not technologies:
        return ["any"]

    detected: list[str] = []
    for tech in technologies:
        tech_lower = tech.lower()
        for db_name, keywords in _DATABASE_KEYWORDS.items():
            if any(kw in tech_lower for kw in keywords) and db_name not in detected:
                detected.append(db_name)

    if not detected:
        return ["any"]

    logger.debug("Databases detected from technologies: %s", detected)
    return detected


# ---------------------------------------------------------------------------
# PayloadDatabase
# ---------------------------------------------------------------------------


class PayloadDatabase:
    """Singleton payload database with context-aware selection.

    Loads ``.jsonl`` files (annotated payloads) and ``.txt`` files (legacy)
    from the payload directory tree. Provides both a simple ``get()`` method
    for backward compatibility and a smart ``select_for_target()`` that
    picks payloads based on scan results.
    """

    _instance: PayloadDatabase | None = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> PayloadDatabase:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._cache: dict[str, dict[str, list[IntelPayload]]] = {}
                    instance._cache_lock = threading.Lock()
                    raw_path = Path(settings.payload_db_path)
                    if raw_path.is_absolute():
                        instance._base_path = raw_path
                    else:
                        project_root = Path(__file__).resolve().parent.parent.parent
                        instance._base_path = project_root / raw_path
                    cls._instance = instance
        return cls._instance

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_jsonl(self, filepath: Path, attack_type: str, technique: str) -> list[IntelPayload]:
        """Load an annotated .jsonl file.

        Each line is a JSON object with at minimum a ``text`` field.
        Missing metadata fields get sensible defaults.
        """
        payloads: list[IntelPayload] = []
        try:
            with open(filepath, encoding="utf-8") as f:
                for line_no, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    try:
                        data = json.loads(stripped)
                        payloads.append(
                            IntelPayload(
                                text=data["text"],
                                attack_type=attack_type,
                                technique=data.get("technique", technique),
                                databases=data.get("databases", ["any"]),
                                contexts=data.get("contexts", ["any"]),
                                waf_bypasses=data.get("waf_bypasses", ["none"]),
                                severity_boost=data.get("severity_boost", 0.5),
                                explanation=data.get("explanation", ""),
                                tags=data.get("tags", []),
                            )
                        )
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.warning(
                            "Skipping malformed line %d in %s: %s",
                            line_no,
                            filepath,
                            e,
                        )
        except OSError as e:
            logger.error("Failed to read payload file %s: %s", filepath, e)
            return []

        logger.info("Loaded %d annotated payloads from %s", len(payloads), filepath)
        return payloads

    def _load_legacy_txt(
        self, filepath: Path, attack_type: str, technique: str
    ) -> list[IntelPayload]:
        """Load a plain .txt file and wrap each line with default metadata.

        Provides backward compatibility with the original flat-file format.
        Lines starting with '#' are comments, empty lines are skipped.
        """
        payloads: list[IntelPayload] = []
        try:
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        payloads.append(
                            IntelPayload(
                                text=stripped,
                                attack_type=attack_type,
                                technique=technique,
                                databases=["any"],
                                contexts=["any"],
                                waf_bypasses=["none"],
                                severity_boost=0.5,
                                explanation="",
                                tags=["legacy"],
                            )
                        )
        except OSError as e:
            logger.error("Failed to read legacy payload file %s: %s", filepath, e)
            return []

        logger.info("Loaded %d legacy payloads from %s", len(payloads), filepath)
        return payloads

    def _load_category(self, attack_type: str, category: str) -> list[IntelPayload]:
        """Load payloads for a category, preferring .jsonl over .txt.

        If both a .jsonl and .txt file exist for the same category, both
        are loaded and merged (JSONL first, then TXT).
        """
        payloads: list[IntelPayload] = []
        base_dir = self._base_path / attack_type

        jsonl_path = base_dir / f"{category}.jsonl"
        txt_path = base_dir / f"{category}.txt"

        if jsonl_path.exists():
            payloads.extend(self._load_jsonl(jsonl_path, attack_type, category))

        if txt_path.exists():
            payloads.extend(self._load_legacy_txt(txt_path, attack_type, category))

        if not payloads:
            logger.warning("No payload files found for %s/%s", attack_type, category)

        return payloads

    def _ensure_loaded(self, attack_type: str) -> dict[str, list[IntelPayload]]:
        """Ensure all categories for an attack type are loaded into the cache."""
        if attack_type in self._cache:
            return self._cache[attack_type]

        with self._cache_lock:
            if attack_type in self._cache:
                return self._cache[attack_type]

            categories: dict[str, list[IntelPayload]] = {}
            type_dir = self._base_path / attack_type

            if type_dir.is_dir():
                # Collect unique category names from both .jsonl and .txt files
                category_names: set[str] = set()
                for f in type_dir.iterdir():
                    if f.suffix in (".jsonl", ".txt") and f.is_file():
                        category_names.add(f.stem)

                for cat_name in sorted(category_names):
                    categories[cat_name] = self._load_category(attack_type, cat_name)
            else:
                logger.debug(
                    "No payload directory for attack type: %s (looked in %s)",
                    attack_type,
                    type_dir,
                )

            self._cache[attack_type] = categories
            return categories

    # ------------------------------------------------------------------
    # Simple access (backward compatible)
    # ------------------------------------------------------------------

    def get(
        self,
        attack_type: str,
        technique: str | None = None,
        database: str | None = None,
        context: str | None = None,
        waf: str | None = None,
        limit: int | None = None,
    ) -> list[IntelPayload]:
        """Get payloads filtered by target context.

        This extends the original ``get()`` interface. When called with
        only ``attack_type`` (and optionally ``limit``), it behaves like
        the legacy version but returns ``IntelPayload`` objects.

        Args:
            attack_type: e.g. "sqli", "xss", "command_injection"
            technique:   e.g. "auth_bypass", "union_based". None = all.
            database:    Filter by target database. None = all.
            context:     Filter by injection context. None = all.
            waf:         Filter by WAF bypass capability. None = all.
            limit:       Max payloads to return. None = all.

        Returns:
            List of IntelPayload objects matching the filters.
        """
        categories = self._ensure_loaded(attack_type)

        if technique is not None:
            payloads = list(categories.get(technique, []))
        else:
            payloads = []
            for cat_payloads in categories.values():
                payloads.extend(cat_payloads)

        # Apply optional filters
        if database is not None:
            db = database.lower()
            payloads = [
                p
                for p in payloads
                if "any" in p.databases or db in [d.lower() for d in p.databases]
            ]

        if context is not None:
            ctx = context.lower()
            payloads = [
                p for p in payloads if "any" in p.contexts or ctx in [c.lower() for c in p.contexts]
            ]

        if waf is not None:
            waf_lower = waf.lower()
            payloads = [
                p
                for p in payloads
                if "none" not in p.waf_bypasses
                and (
                    waf_lower in [w.lower() for w in p.waf_bypasses]
                    or "generic" in [w.lower() for w in p.waf_bypasses]
                )
            ]

        if limit is not None:
            payloads = payloads[:limit]

        return payloads

    def get_texts(
        self,
        attack_type: str,
        category: str | None = None,
        limit: int | None = None,
    ) -> list[str]:
        """Get payload texts only (backward compatible with old API).

        Drop-in replacement for the original ``get()`` that returned
        plain strings. The ``category`` parameter maps to ``technique``.
        """
        intel_payloads = self.get(
            attack_type=attack_type,
            technique=category,
            limit=limit,
        )
        return [p.text for p in intel_payloads]

    # ------------------------------------------------------------------
    # Smart selection
    # ------------------------------------------------------------------

    def select_for_target(
        self,
        attack_type: str,
        technologies: list[str],
        headers: dict | None = None,
        limit: int | None = None,
    ) -> list[IntelPayload]:
        """Smart selection: pick the best payloads for a specific target.

        This is the key differentiator of the contextual intelligence system.
        It:
        1. Detects database engine from the technology list
        2. Detects WAF from response headers
        3. Filters payloads matching the detected context
        4. Ranks by severity_boost and historical success rate
        5. Returns the top ``limit`` payloads

        Args:
            attack_type:   The attack category (sqli, xss, etc.).
            technologies:  Technologies detected by the scanner.
            headers:       Raw HTTP response headers (for WAF detection).
            limit:         Max payloads to return.

        Returns:
            Ranked list of IntelPayload objects.
        """
        databases = _detect_database(technologies)
        waf = _detect_waf(headers)

        logger.info(
            "Smart selection for %s: databases=%s, waf=%s",
            attack_type,
            databases,
            waf,
        )

        # Get all payloads for this attack type
        all_payloads = self.get(attack_type)

        if not all_payloads:
            logger.warning("No payloads available for attack type: %s", attack_type)
            return []

        # Score each payload based on relevance to the target
        scored: list[tuple[float, IntelPayload]] = []

        for payload in all_payloads:
            score = payload.severity_boost

            # Database relevance bonus
            if "any" not in databases:
                payload_dbs = [d.lower() for d in payload.databases]
                if "any" in payload_dbs:
                    # Generic payloads get a small bonus
                    score += 0.1
                elif any(db in payload_dbs for db in databases):
                    # Database-specific payloads that match get a big bonus
                    score += 0.3
                else:
                    # Payloads for other databases get penalized
                    score -= 0.3

            # WAF handling
            if waf is not None:
                payload_wafs = [w.lower() for w in payload.waf_bypasses]
                if waf.lower() in payload_wafs or "generic" in payload_wafs:
                    # Payload is designed to bypass this WAF
                    score += 0.25
                elif "none" in payload_wafs:
                    # Payload has no WAF bypass — risky if WAF is present
                    score -= 0.15

            # Historical effectiveness boost from feedback tracker
            primary_tech = databases[0] if databases and databases[0] != "any" else ""
            if primary_tech:
                feedback_boost = feedback_tracker.get_boost(payload.text, primary_tech)
                score += feedback_boost * 0.2

            scored.append((score, payload))

        # Sort by score descending
        scored.sort(key=lambda x: x[0], reverse=True)

        # De-duplicate by payload text
        seen_texts: set[str] = set()
        unique: list[IntelPayload] = []
        for _, payload in scored:
            if payload.text not in seen_texts:
                seen_texts.add(payload.text)
                unique.append(payload)

        if limit is not None:
            unique = unique[:limit]

        logger.info(
            "Smart selection returned %d payloads (from %d candidates)",
            len(unique),
            len(all_payloads),
        )
        return unique

    # ------------------------------------------------------------------
    # Feedback recording
    # ------------------------------------------------------------------

    def record_result(self, payload_text: str, technology: str, success: bool) -> None:
        """Record a payload execution result for the feedback loop.

        Delegates to the :class:`FeedbackTracker` singleton.

        Args:
            payload_text: The payload string that was tested.
            technology:   The technology it was tested against.
            success:      Whether the payload triggered a vulnerability.
        """
        feedback_tracker.record(payload_text, technology, success)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def categories(self, attack_type: str) -> list[str]:
        """List available categories for an attack type."""
        categories = self._ensure_loaded(attack_type)
        return sorted(categories.keys())

    def get_stats(self) -> dict:
        """Return payload database statistics and effectiveness data."""
        result: dict[str, int] = {}

        if not self._base_path.is_dir():
            logger.warning("Payload database path does not exist: %s", self._base_path)
            return {"payload_counts": result, "feedback": feedback_tracker.get_stats_summary()}

        for type_dir in sorted(self._base_path.iterdir()):
            if type_dir.is_dir():
                attack_type = type_dir.name
                categories = self._ensure_loaded(attack_type)
                total = sum(len(payloads) for payloads in categories.values())
                if total > 0:
                    result[attack_type] = total

        return {
            "payload_counts": result,
            "feedback": feedback_tracker.get_stats_summary(),
        }

    def stats(self) -> dict[str, int]:
        """Return count of payloads per attack type (backward compatible)."""
        full_stats = self.get_stats()
        return full_stats.get("payload_counts", {})


# Module-level convenience singleton
payload_db = PayloadDatabase()
