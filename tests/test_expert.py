"""Tests du systeme expert.

Verifie que les regles s'activent dans le bon ordre
et produisent les bons vecteurs d'attaque.
"""

import json
from pathlib import Path

import pytest

from src.models import ScanResult
from src.expert.engine import ExpertEngine
from src.expert.facts import Fact, scan_result_to_facts
from src.expert.rules import get_all_rules

FIXTURES_DIR = Path(__file__).parent.parent / "data" / "fixtures"


class TestFactExtraction:
    """Tests de la conversion ScanResult → Faits."""

    def test_scan_result_to_facts(self):
        data = json.loads((FIXTURES_DIR / "scan_result.json").read_text())
        scan = ScanResult.model_validate(data)
        facts = scan_result_to_facts(scan)

        assert len(facts) > 0

        # Verifier la presence des types de faits attendus
        fact_types = {f.type for f in facts}
        assert "open_port" in fact_types
        assert "endpoint" in fact_types
        assert "technology" in fact_types
        assert "missing_header" in fact_types
        assert "form" in fact_types

    def test_technology_facts(self):
        data = json.loads((FIXTURES_DIR / "scan_result.json").read_text())
        scan = ScanResult.model_validate(data)
        facts = scan_result_to_facts(scan)

        tech_facts = [f for f in facts if f.type == "technology"]
        tech_names = {f.attributes["name"] for f in tech_facts}
        assert "SQLite" in tech_names
        assert "Node.js" in tech_names


class TestExpertEngine:
    """Tests du moteur de chainage avant."""

    def _run_engine(self) -> tuple:
        """Helper : charge la fixture et lance le moteur."""
        data = json.loads((FIXTURES_DIR / "scan_result.json").read_text())
        scan = ScanResult.model_validate(data)
        facts = scan_result_to_facts(scan)

        engine = ExpertEngine()
        engine.inject_facts(facts)
        engine.load_rules(get_all_rules())
        plan = engine.run()
        return engine, plan

    def test_rules_fire(self):
        engine, plan = self._run_engine()
        assert len(plan.rules_fired) >= 3

    def test_sql_injection_fires_first(self):
        engine, plan = self._run_engine()
        assert "SQL_INJECTION" in plan.rules_fired
        # SQL_INJECTION doit s'activer avant SQL_INJECTION_CRITICAL
        idx_sqli = plan.rules_fired.index("SQL_INJECTION")
        idx_critical = plan.rules_fired.index("SQL_INJECTION_CRITICAL")
        assert idx_sqli < idx_critical, "SQL_INJECTION doit s'activer avant SQL_INJECTION_CRITICAL"

    def test_xss_fires(self):
        engine, plan = self._run_engine()
        assert "XSS_REFLECTED" in plan.rules_fired

    def test_chaining_produces_critical(self):
        """Verifie que le chainage eleve la severite a CRITICAL."""
        engine, plan = self._run_engine()
        critical_vectors = [
            v for v in plan.vectors
            if (v.severity.value if hasattr(v.severity, 'value') else v.severity) == "CRITICAL"
        ]
        assert len(critical_vectors) >= 1, "Au moins un vecteur doit etre CRITICAL apres chainage"

    def test_attack_vectors_generated(self):
        engine, plan = self._run_engine()
        assert len(plan.vectors) >= 2  # Au moins SQLi + XSS
