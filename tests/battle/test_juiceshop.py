"""Battle test: RedSimulator vs OWASP Juice Shop.

Runs the expert system against Juice Shop fixture data and verifies
that detection meets the baseline expectations.  These tests work
WITHOUT a live Docker target by using the stored scan fixture.
"""

import json
from pathlib import Path

from src.expert import ExpertEngine, get_all_rules, scan_result_to_facts
from src.models import ScanResult
from src.models.attack_plan import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "fixtures"
_BASELINE_DIR = Path(__file__).resolve().parent / "baselines"

_SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def _load_baseline() -> dict:
    return json.loads((_BASELINE_DIR / "juiceshop_expected.json").read_text())


def _run_expert_on_fixture() -> tuple[ScanResult, "AttackPlan", ExpertEngine]:  # noqa: F821
    """Load the Juice Shop scan fixture and run the expert engine."""
    scan = ScanResult.model_validate(json.loads((_FIXTURE_DIR / "scan_result.json").read_text()))
    facts = scan_result_to_facts(scan)
    engine = ExpertEngine()
    engine.inject_facts(facts)
    engine.load_rules(get_all_rules())
    plan = engine.run(scan=scan, llm_second_pass=False)
    return scan, plan, engine


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestJuiceShop:
    """Run the expert system against the Juice Shop fixture and verify detection."""

    baseline_path = _BASELINE_DIR / "juiceshop_expected.json"

    def test_minimum_rules_fire(self):
        """Verify that at least *min_rules_fired* rules activate."""
        baseline = _load_baseline()
        _scan, _plan, engine = _run_expert_on_fixture()
        assert len(engine.fired_rules) >= baseline["min_rules_fired"], (
            f"Expected >= {baseline['min_rules_fired']} rules to fire, "
            f"got {len(engine.fired_rules)}: {engine.fired_rules}"
        )

    def test_expected_attack_types_detected(self):
        """Verify that all expected attack types are present in the plan."""
        baseline = _load_baseline()
        _scan, plan, _engine = _run_expert_on_fixture()
        detected_types = {v.attack_type.value for v in plan.vectors}
        for expected in baseline["expected_attack_types"]:
            assert expected in detected_types, (
                f"Attack type '{expected}' not detected. Found: {sorted(detected_types)}"
            )

    def test_critical_findings(self):
        """Verify CRITICAL severity findings exist when the baseline requires it."""
        baseline = _load_baseline()
        if not baseline.get("must_have_critical"):
            return
        _scan, plan, _engine = _run_expert_on_fixture()
        severities = {v.severity.value for v in plan.vectors}
        assert "CRITICAL" in severities, (
            "Baseline requires CRITICAL findings but none were detected. "
            f"Severities found: {sorted(severities)}"
        )

    def test_known_vulnerabilities(self):
        """Verify that specific known vulnerabilities are detected."""
        baseline = _load_baseline()
        _scan, plan, _engine = _run_expert_on_fixture()

        for vuln in baseline.get("known_vulnerabilities", []):
            vuln_type = vuln["type"]
            endpoint = vuln.get("endpoint", "")
            endpoint_contains = vuln.get("endpoint_contains", "")
            min_severity = vuln.get("min_severity", "LOW")

            matching = [
                v
                for v in plan.vectors
                if v.attack_type.value == vuln_type
                and (
                    (endpoint and v.target_endpoint == endpoint)
                    or (endpoint_contains and endpoint_contains in v.target_endpoint)
                    or (not endpoint and not endpoint_contains)
                )
            ]

            assert matching, (
                f"Known vulnerability not detected: type={vuln_type}, "
                f"endpoint={endpoint or endpoint_contains}"
            )

            # Check minimum severity
            min_sev_value = _SEVERITY_ORDER[Severity(min_severity)]
            best = max(matching, key=lambda v: _SEVERITY_ORDER[v.severity])
            assert _SEVERITY_ORDER[best.severity] >= min_sev_value, (
                f"Vulnerability {vuln_type} at {endpoint or endpoint_contains} "
                f"has severity {best.severity.value}, expected >= {min_severity}"
            )

    def test_minimum_vectors(self):
        """Verify that the plan contains at least *min_vectors* attack vectors."""
        baseline = _load_baseline()
        _scan, plan, _engine = _run_expert_on_fixture()
        assert len(plan.vectors) >= baseline["min_vectors"], (
            f"Expected >= {baseline['min_vectors']} vectors, got {len(plan.vectors)}"
        )

    def test_no_regression_from_baseline(self):
        """Compare the current detection rate against the stored baseline.

        Ensures the number of detected vectors and fired rules does not
        drop below 90 % of the baseline expectations.
        """
        baseline = _load_baseline()
        _scan, plan, engine = _run_expert_on_fixture()

        # Vectors count should not regress below 90 % of baseline min
        min_vectors = int(baseline["min_vectors"] * 0.9)
        assert len(plan.vectors) >= min_vectors, (
            f"Regression: vectors dropped to {len(plan.vectors)} "
            f"(baseline min = {baseline['min_vectors']})"
        )

        # Rules fired should not regress below 90 % of baseline min
        min_rules = int(baseline["min_rules_fired"] * 0.9)
        assert len(engine.fired_rules) >= min_rules, (
            f"Regression: rules_fired dropped to {len(engine.fired_rules)} "
            f"(baseline min = {baseline['min_rules_fired']})"
        )
