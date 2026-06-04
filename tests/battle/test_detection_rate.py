"""Detection rate regression tests.

These tests verify core detection capabilities WITHOUT requiring any
Docker target.  They construct synthetic facts or use existing fixture
data to ensure the expert system, passive analyzer, and payload
database maintain their expected detection rates.
"""

import json
from pathlib import Path

from src.expert import ExpertEngine, get_all_rules, scan_result_to_facts
from src.expert.facts import Fact
from src.models import ScanResult
from src.models.attack_plan import AttackType

_FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "fixtures"


# ---------------------------------------------------------------------------
# Helpers to build minimal fact sets
# ---------------------------------------------------------------------------


def _minimal_sqli_facts() -> list[Fact]:
    """Create the minimum facts needed to trigger SQLi detection."""
    return [
        Fact(type="technology", attributes={"name": "SQLite"}),
        Fact(
            type="form",
            attributes={
                "endpoint": "/login",
                "fields": ["username", "password"],
                "method": "POST",
            },
        ),
        Fact(
            type="endpoint",
            attributes={
                "path": "/login",
                "method": "POST",
                "status_code": 200,
                "auth_required": False,
                "parameters": ["username", "password"],
            },
        ),
    ]


def _minimal_xss_facts() -> list[Fact]:
    """Create facts for a POST endpoint without CSP."""
    return [
        Fact(
            type="endpoint",
            attributes={
                "path": "/feedback",
                "method": "POST",
                "status_code": 200,
                "auth_required": False,
                "parameters": ["comment"],
            },
        ),
        Fact(
            type="form",
            attributes={
                "endpoint": "/feedback",
                "fields": ["comment"],
                "method": "POST",
            },
        ),
        Fact(type="missing_header", attributes={"header": "Content-Security-Policy"}),
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDetectionRate:
    """Ensure detection capabilities do not regress."""

    def test_sqli_detection_on_forms(self):
        """A form backed by SQLite technology should trigger SQLi detection."""
        facts = _minimal_sqli_facts()
        engine = ExpertEngine()
        engine.inject_facts(facts)
        engine.load_rules(get_all_rules())
        plan = engine.run(llm_second_pass=False)

        sqli_vectors = [v for v in plan.vectors if v.attack_type == AttackType.sqli]
        assert len(sqli_vectors) > 0, (
            "SQLi should be detected when a form + SQLite technology are present. "
            f"Fired rules: {engine.fired_rules}"
        )

    def test_xss_detection_on_post_without_csp(self):
        """A POST endpoint without CSP should trigger XSS detection."""
        facts = _minimal_xss_facts()
        engine = ExpertEngine()
        engine.inject_facts(facts)
        engine.load_rules(get_all_rules())
        plan = engine.run(llm_second_pass=False)

        xss_vectors = [v for v in plan.vectors if v.attack_type == AttackType.xss]
        assert len(xss_vectors) > 0, (
            f"XSS should be detected on a POST form without CSP. Fired rules: {engine.fired_rules}"
        )

    def test_chaining_elevates_severity(self):
        """Chaining rules should elevate severity when conditions are met.

        When multiple attack vectors coexist for the same endpoint the
        chaining rules should raise at least one vector to CRITICAL.
        """
        scan = ScanResult.model_validate(
            json.loads((_FIXTURE_DIR / "scan_result.json").read_text())
        )
        facts = scan_result_to_facts(scan)
        engine = ExpertEngine()
        engine.inject_facts(facts)
        engine.load_rules(get_all_rules())
        plan = engine.run(scan=scan, llm_second_pass=False)

        severities = [v.severity.value for v in plan.vectors]
        assert "CRITICAL" in severities, (
            "Chaining rules should elevate at least one vector to CRITICAL. "
            f"Severities: {severities}"
        )

    def test_passive_checks_detect_missing_headers(self):
        """Passive scanning should detect common missing security headers."""
        from src.passive.analyzer import PassiveAnalyzer

        analyzer = PassiveAnalyzer()
        findings = analyzer.analyze_response(
            url="http://test.local",
            status_code=200,
            headers={"Server": "Apache/2.4.49"},  # No security headers
            body="<html></html>",
        )
        assert len(findings) >= 3, (
            "Should find at least 3 missing-header findings (HSTS, CSP, X-Frame-Options). "
            f"Found {len(findings)}: {[f.title for f in findings]}"
        )

    def test_payload_db_coverage(self):
        """Verify that the payload database has adequate coverage."""
        from src.generator.payload_db import payload_db

        stats = payload_db.get_stats()
        counts = stats["payload_counts"]
        assert counts.get("sqli", 0) >= 100, f"SQLi payloads too low: {counts.get('sqli', 0)}"
        assert counts.get("xss", 0) >= 50, f"XSS payloads too low: {counts.get('xss', 0)}"
        assert counts.get("command_injection", 0) >= 30, (
            f"Command injection payloads too low: {counts.get('command_injection', 0)}"
        )

    def test_fixture_pipeline_attack_types(self):
        """Verify that running the full fixture produces multiple attack types."""
        scan = ScanResult.model_validate(
            json.loads((_FIXTURE_DIR / "scan_result.json").read_text())
        )
        facts = scan_result_to_facts(scan)
        engine = ExpertEngine()
        engine.inject_facts(facts)
        engine.load_rules(get_all_rules())
        plan = engine.run(scan=scan, llm_second_pass=False)

        attack_types = {v.attack_type.value for v in plan.vectors}
        assert len(attack_types) >= 3, (
            f"Should detect >= 3 attack types, found {len(attack_types)}: {sorted(attack_types)}"
        )
