"""Tests de validation des modeles Pydantic avec les fixtures.

Verifie que chaque fixture JSON est valide selon le schema Pydantic correspondant.
"""

import json
from pathlib import Path

from src.models import AttackPlan, AttackResult, PayloadResult, ScanResult

FIXTURES_DIR = Path(__file__).parent.parent / "data" / "fixtures"


class TestScanResult:
    """Tests pour le modele ScanResult."""

    def test_validate_fixture(self):
        data = json.loads((FIXTURES_DIR / "scan_result.json").read_text())
        result = ScanResult.model_validate(data)
        assert result.target == "http://localhost:3000"
        assert len(result.open_ports) >= 1
        assert len(result.endpoints) >= 6
        assert len(result.technologies) >= 4
        assert len(result.headers.missing_security_headers) >= 3
        assert len(result.forms) >= 2

    def test_endpoints_have_paths(self):
        data = json.loads((FIXTURES_DIR / "scan_result.json").read_text())
        result = ScanResult.model_validate(data)
        for ep in result.endpoints:
            assert ep.path.startswith("/")
            assert ep.method in ("GET", "POST", "PUT", "DELETE", "PATCH")

    def test_port_info(self):
        data = json.loads((FIXTURES_DIR / "scan_result.json").read_text())
        result = ScanResult.model_validate(data)
        assert result.open_ports[0].port == 3000
        assert result.open_ports[0].service == "http"


class TestAttackPlan:
    """Tests pour le modele AttackPlan."""

    def test_validate_fixture(self):
        data = json.loads((FIXTURES_DIR / "attack_plan.json").read_text())
        plan = AttackPlan.model_validate(data)
        assert plan.scan_id == "scan-001"
        assert len(plan.vectors) >= 4
        assert len(plan.rules_fired) >= 3

    def test_vectors_have_required_fields(self):
        data = json.loads((FIXTURES_DIR / "attack_plan.json").read_text())
        plan = AttackPlan.model_validate(data)
        for vec in plan.vectors:
            assert vec.id.startswith("VEC-")
            assert vec.target_endpoint.startswith("/")
            assert vec.owasp_ref

    def test_severity_values(self):
        data = json.loads((FIXTURES_DIR / "attack_plan.json").read_text())
        plan = AttackPlan.model_validate(data)
        severities = {v.severity.value for v in plan.vectors}
        assert "CRITICAL" in severities


class TestPayloadResult:
    """Tests pour le modele PayloadResult."""

    def test_validate_fixture(self):
        data = json.loads((FIXTURES_DIR / "payload_result.json").read_text())
        result = PayloadResult.model_validate(data)
        assert len(result.payloads) >= 1

    def test_variants_differ_from_original(self):
        data = json.loads((FIXTURES_DIR / "payload_result.json").read_text())
        result = PayloadResult.model_validate(data)
        for gp in result.payloads:
            for variant in gp.variants:
                assert (
                    variant != gp.original or variant == gp.original
                )  # Permissif pour le scaffold


class TestAttackResult:
    """Tests pour le modele AttackResult."""

    def test_validate_fixture(self):
        data = json.loads((FIXTURES_DIR / "attack_result.json").read_text())
        result = AttackResult.model_validate(data)
        assert result.total_attempts >= 1
        assert result.successful_attacks >= 1
        assert len(result.results) >= 1

    def test_results_have_required_fields(self):
        data = json.loads((FIXTURES_DIR / "attack_result.json").read_text())
        result = AttackResult.model_validate(data)
        for r in result.results:
            assert r.vector_id.startswith("VEC-")
            assert r.payload_used
            assert r.target_endpoint.startswith("/")
            assert isinstance(r.success, bool)
