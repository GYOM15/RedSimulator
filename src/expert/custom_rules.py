"""User-defined rules created through the API.

Custom rules are defined as JSON with conditions and actions expressed
as simple declarative patterns, not Python code. They are stored on
disk at data/custom_rules.json.

Security: we never eval() or exec() user input. The rule compiler
converts JSON conditions to Python functions safely by matching
against a fixed set of known condition/action types.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from src.infra.logging import get_logger

from .engine import Rule
from .facts import Fact

logger = get_logger(__name__)

# Allowed condition types — anything else is rejected.
_VALID_CONDITION_TYPES = {"fact_exists", "fact_count", "vector_exists"}

# Allowed action types — anything else is rejected.
_VALID_ACTION_TYPES = {"create_vector", "elevate_severity"}

# Allowed severity values.
_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@dataclass
class CustomRuleDefinition:
    """A user-defined rule in declarative format.

    Condition format examples::

        {"type": "fact_exists", "fact_type": "endpoint", "attrs": {"method": "POST"}}
        {"type": "fact_exists", "fact_type": "technology", "attrs": {"name_contains": "sql"}}
        {"type": "fact_count", "fact_type": "missing_header", "min_count": 2}
        {"type": "vector_exists", "attack_type": "sqli"}

    Action format examples::

        {"type": "create_vector", "attack_type": "sqli", "severity": "HIGH",
         "owasp_ref": "A03:2021", "rationale": ["reason"], "base_payloads": ["payload"]}
        {"type": "elevate_severity", "attack_type": "sqli", "new_severity": "CRITICAL"}
    """

    name: str
    description: str
    priority: int = 5
    enabled: bool = True
    conditions: list[dict] = field(default_factory=list)
    action: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CustomRuleDefinition:
        """Deserialize from a dict (e.g. loaded from JSON)."""
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            priority=data.get("priority", 5),
            enabled=data.get("enabled", True),
            conditions=data.get("conditions", []),
            action=data.get("action", {}),
        )


class CustomRuleEngine:
    """Loads and converts custom rule definitions into executable Rules.

    Thread-safe: all reads/writes to the JSON file and the internal
    rule list are protected by a reentrant lock.
    """

    def __init__(self, rules_path: str = "data/custom_rules.json"):
        self.rules_path = Path(rules_path)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> list[Rule]:
        """Load custom rules and convert to executable Rule instances.

        Returns only rules that are currently enabled. Invalid rules
        are logged and skipped rather than crashing the engine.
        """
        definitions = self.list_rules()
        rules: list[Rule] = []

        for defn in definitions:
            if not defn.enabled:
                logger.debug("Skipping disabled custom rule: %s", defn.name)
                continue

            try:
                self._validate_definition(defn)
                conditions_fn = self._compile_conditions(defn.conditions)
                action_fn = self._compile_action(defn.action, defn.name)
                rules.append(
                    Rule(
                        name=f"CUSTOM:{defn.name}",
                        conditions=conditions_fn,
                        action=action_fn,
                        priority=defn.priority,
                    )
                )
            except Exception:
                logger.exception("Failed to compile custom rule '%s'; skipping", defn.name)

        logger.info("Loaded %d custom rules", len(rules))
        return rules

    def save_rule(self, rule_def: CustomRuleDefinition) -> None:
        """Save a new custom rule (or overwrite one with the same name)."""
        self._validate_definition(rule_def)

        with self._lock:
            existing = self._read_file()
            # Replace if a rule with the same name already exists.
            existing = [r for r in existing if r["name"] != rule_def.name]
            existing.append(rule_def.to_dict())
            self._write_file(existing)

        logger.info("Saved custom rule: %s", rule_def.name)

    def delete_rule(self, name: str) -> bool:
        """Delete a custom rule by name. Returns True if found and deleted."""
        with self._lock:
            existing = self._read_file()
            before = len(existing)
            existing = [r for r in existing if r["name"] != name]
            if len(existing) == before:
                return False
            self._write_file(existing)

        logger.info("Deleted custom rule: %s", name)
        return True

    def list_rules(self) -> list[CustomRuleDefinition]:
        """List all custom rules."""
        with self._lock:
            raw = self._read_file()
        return [CustomRuleDefinition.from_dict(r) for r in raw]

    def toggle_rule(self, name: str) -> bool | None:
        """Toggle the enabled state of a custom rule.

        Returns the new enabled state, or None if the rule was not found.
        """
        with self._lock:
            existing = self._read_file()
            for r in existing:
                if r["name"] == name:
                    r["enabled"] = not r.get("enabled", True)
                    self._write_file(existing)
                    logger.info(
                        "Toggled custom rule '%s' -> enabled=%s",
                        name,
                        r["enabled"],
                    )
                    return r["enabled"]
        return None

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_definition(defn: CustomRuleDefinition) -> None:
        """Validate a custom rule definition.

        Raises ValueError with a human-readable message when invalid.
        """
        if not defn.name or not defn.name.strip():
            raise ValueError("Rule name must not be empty")

        if not defn.conditions:
            raise ValueError("Rule must have at least one condition")

        if not defn.action:
            raise ValueError("Rule must have an action")

        # Validate each condition
        for i, cond in enumerate(defn.conditions):
            ctype = cond.get("type")
            if ctype not in _VALID_CONDITION_TYPES:
                raise ValueError(
                    f"Condition #{i}: unknown type '{ctype}'. "
                    f"Allowed: {sorted(_VALID_CONDITION_TYPES)}"
                )

            if ctype in ("fact_exists", "fact_count") and "fact_type" not in cond:
                raise ValueError(f"Condition #{i}: '{ctype}' requires 'fact_type'")

            if ctype == "fact_count":
                if "min_count" not in cond:
                    raise ValueError(f"Condition #{i}: 'fact_count' requires 'min_count'")
                if not isinstance(cond["min_count"], int) or cond["min_count"] < 0:
                    raise ValueError(f"Condition #{i}: 'min_count' must be a non-negative integer")

            if ctype == "vector_exists" and "attack_type" not in cond:
                raise ValueError(f"Condition #{i}: 'vector_exists' requires 'attack_type'")

        # Validate action
        atype = defn.action.get("type")
        if atype not in _VALID_ACTION_TYPES:
            raise ValueError(
                f"Unknown action type '{atype}'. Allowed: {sorted(_VALID_ACTION_TYPES)}"
            )

        if atype == "create_vector":
            for required in ("attack_type", "severity"):
                if required not in defn.action:
                    raise ValueError(f"Action 'create_vector' requires '{required}'")
            if defn.action["severity"] not in _VALID_SEVERITIES:
                raise ValueError(
                    f"Invalid severity '{defn.action['severity']}'. "
                    f"Allowed: {sorted(_VALID_SEVERITIES)}"
                )

        if atype == "elevate_severity":
            for required in ("attack_type", "new_severity"):
                if required not in defn.action:
                    raise ValueError(f"Action 'elevate_severity' requires '{required}'")
            if defn.action["new_severity"] not in _VALID_SEVERITIES:
                raise ValueError(
                    f"Invalid severity '{defn.action['new_severity']}'. "
                    f"Allowed: {sorted(_VALID_SEVERITIES)}"
                )

    # ------------------------------------------------------------------
    # Condition compiler
    # ------------------------------------------------------------------

    def _compile_conditions(self, conditions: list[dict]) -> Callable[[list[Fact]], bool]:
        """Convert declarative conditions to a callable.

        All conditions must be satisfied (AND logic).
        """
        checks: list[Callable[[list[Fact]], bool]] = []

        for cond in conditions:
            ctype = cond["type"]

            if ctype == "fact_exists":
                checks.append(self._make_fact_exists_check(cond))
            elif ctype == "fact_count":
                checks.append(self._make_fact_count_check(cond))
            elif ctype == "vector_exists":
                checks.append(self._make_vector_exists_check(cond))

        def all_conditions(memory: list[Fact]) -> bool:
            return all(check(memory) for check in checks)

        return all_conditions

    @staticmethod
    def _make_fact_exists_check(cond: dict) -> Callable[[list[Fact]], bool]:
        """Build a checker for {'type': 'fact_exists', ...}."""
        fact_type = cond["fact_type"]
        attrs = cond.get("attrs", {})

        def check(memory: list[Fact]) -> bool:
            for fact in memory:
                if fact.type != fact_type:
                    continue
                match = True
                for key, value in attrs.items():
                    # Support 'name_contains' as a substring match.
                    if key.endswith("_contains"):
                        base_key = key[: -len("_contains")]
                        fact_val = fact.attributes.get(base_key, "")
                        if isinstance(value, str) and isinstance(fact_val, str):
                            if value.lower() not in fact_val.lower():
                                match = False
                                break
                        else:
                            match = False
                            break
                    else:
                        if fact.attributes.get(key) != value:
                            match = False
                            break
                if match:
                    return True
            return False

        return check

    @staticmethod
    def _make_fact_count_check(cond: dict) -> Callable[[list[Fact]], bool]:
        """Build a checker for {'type': 'fact_count', ...}."""
        fact_type = cond["fact_type"]
        min_count = cond["min_count"]

        def check(memory: list[Fact]) -> bool:
            count = sum(1 for f in memory if f.type == fact_type)
            return count >= min_count

        return check

    @staticmethod
    def _make_vector_exists_check(cond: dict) -> Callable[[list[Fact]], bool]:
        """Build a checker for {'type': 'vector_exists', ...}."""
        attack_type = cond["attack_type"]

        def check(memory: list[Fact]) -> bool:
            return any(
                f.type == "attack_vector" and f.attributes.get("attack_type") == attack_type
                for f in memory
            )

        return check

    # ------------------------------------------------------------------
    # Action compiler
    # ------------------------------------------------------------------

    def _compile_action(self, action: dict, rule_name: str) -> Callable[[list[Fact]], list[Fact]]:
        """Convert a declarative action to a callable."""
        atype = action["type"]

        if atype == "create_vector":
            return self._make_create_vector_action(action, rule_name)
        elif atype == "elevate_severity":
            return self._make_elevate_severity_action(action, rule_name)
        else:
            raise ValueError(f"Unknown action type: {atype}")

    @staticmethod
    def _make_create_vector_action(
        action: dict, rule_name: str
    ) -> Callable[[list[Fact]], list[Fact]]:
        """Build an action that creates a new attack vector fact."""
        attack_type = action["attack_type"]
        severity = action["severity"]
        owasp_ref = action.get("owasp_ref", "")
        rationale = action.get("rationale", [f"Custom rule: {rule_name}"])
        base_payloads = action.get("base_payloads", [])
        target_endpoint = action.get("target_endpoint", "/")
        target_fields = action.get("target_fields", [])

        def create_vector(memory: list[Fact]) -> list[Fact]:
            # Check if this rule has already produced a vector for this attack type.
            already_exists = any(
                f.type == "attack_vector"
                and f.attributes.get("attack_type") == attack_type
                and f.source == f"rule:CUSTOM:{rule_name}"
                for f in memory
            )
            if already_exists:
                return []

            existing_vectors = [f for f in memory if f.type == "attack_vector"]
            next_id = len(existing_vectors) + 1
            vector_id = f"VEC-{next_id:03d}"

            return [
                Fact(
                    type="attack_vector",
                    attributes={
                        "id": vector_id,
                        "attack_type": attack_type,
                        "target_endpoint": target_endpoint,
                        "target_fields": target_fields,
                        "severity": severity,
                        "owasp_ref": owasp_ref,
                        "rationale": list(rationale),
                        "base_payloads": list(base_payloads),
                    },
                    source=f"rule:CUSTOM:{rule_name}",
                )
            ]

        return create_vector

    @staticmethod
    def _make_elevate_severity_action(
        action: dict, rule_name: str
    ) -> Callable[[list[Fact]], list[Fact]]:
        """Build an action that elevates severity on matching vectors."""
        target_attack_type = action["attack_type"]
        new_severity = action["new_severity"]

        def elevate_severity(memory: list[Fact]) -> list[Fact]:
            elevations: list[Fact] = []

            for fact in memory:
                if (
                    fact.type == "attack_vector"
                    and fact.attributes.get("attack_type") == target_attack_type
                    and fact.attributes.get("severity") != new_severity
                ):
                    old_severity = fact.attributes["severity"]
                    fact.attributes["severity"] = new_severity
                    fact.attributes.setdefault("rationale", []).append(
                        f"Elevated to {new_severity} by custom rule: {rule_name}"
                    )
                    elevations.append(
                        Fact(
                            type="severity_elevation",
                            attributes={
                                "vector_id": fact.attributes["id"],
                                "from": old_severity,
                                "to": new_severity,
                                "reason": f"Custom rule: {rule_name}",
                            },
                            source=f"rule:CUSTOM:{rule_name}",
                        )
                    )

            return elevations

        return elevate_severity

    # ------------------------------------------------------------------
    # File I/O (thread-safe)
    # ------------------------------------------------------------------

    def _read_file(self) -> list[dict]:
        """Read custom rules from the JSON file. Returns [] if missing."""
        if not self.rules_path.exists():
            return []
        try:
            data = json.loads(self.rules_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
            logger.warning("Custom rules file is not a JSON array; ignoring")
            return []
        except (json.JSONDecodeError, OSError):
            logger.exception("Failed to read custom rules file")
            return []

    def _write_file(self, rules: list[dict]) -> None:
        """Write custom rules to the JSON file, creating parent dirs."""
        self.rules_path.parent.mkdir(parents=True, exist_ok=True)
        self.rules_path.write_text(
            json.dumps(rules, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
