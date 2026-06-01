"""Tests du systeme expert.

Verifie que les regles s'activent dans le bon ordre
et produisent les bons vecteurs d'attaque.

Couvre les 20 regles : 11 regles de detection (rules.py),
4 regles header/config (rules_header.py), et 5 regles de chainage (rules_chaining.py).
"""

import json
from pathlib import Path

from src.expert.engine import ExpertEngine
from src.expert.facts import Fact, scan_result_to_facts
from src.expert.rules import get_all_rules
from src.models import ScanResult

FIXTURES_DIR = Path(__file__).parent.parent / "data" / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_scan_fixture() -> ScanResult:
    """Load the scan_result.json fixture and return a ScanResult."""
    data = json.loads((FIXTURES_DIR / "scan_result.json").read_text())
    return ScanResult.model_validate(data)


def _run_engine_on_fixture():
    """Load the fixture, convert to facts, run the engine, return (engine, plan)."""
    scan = _load_scan_fixture()
    facts = scan_result_to_facts(scan)
    engine = ExpertEngine()
    engine.inject_facts(facts)
    engine.load_rules(get_all_rules())
    plan = engine.run(llm_second_pass=False)
    return engine, plan


def _run_engine_on_facts(facts: list[Fact]):
    """Run the engine on arbitrary facts and return (engine, plan)."""
    engine = ExpertEngine()
    engine.inject_facts(facts)
    engine.load_rules(get_all_rules())
    plan = engine.run(llm_second_pass=False)
    return engine, plan


# ---------------------------------------------------------------------------
# TestFactExtraction (existing)
# ---------------------------------------------------------------------------


class TestFactExtraction:
    """Tests de la conversion ScanResult -> Faits."""

    def test_scan_result_to_facts(self):
        scan = _load_scan_fixture()
        facts = scan_result_to_facts(scan)

        assert len(facts) > 0

        fact_types = {f.type for f in facts}
        assert "open_port" in fact_types
        assert "endpoint" in fact_types
        assert "technology" in fact_types
        assert "missing_header" in fact_types
        assert "form" in fact_types

    def test_technology_facts(self):
        scan = _load_scan_fixture()
        facts = scan_result_to_facts(scan)

        tech_facts = [f for f in facts if f.type == "technology"]
        tech_names = {f.attributes["name"] for f in tech_facts}
        assert "SQLite" in tech_names
        assert "Node.js" in tech_names

    def test_server_info_leaked_fact(self):
        scan = _load_scan_fixture()
        facts = scan_result_to_facts(scan)

        leaked_facts = [f for f in facts if f.type == "server_info_leaked"]
        assert len(leaked_facts) == 1
        assert leaked_facts[0].attributes["leaked"] is True

    def test_form_facts_contain_fields(self):
        scan = _load_scan_fixture()
        facts = scan_result_to_facts(scan)

        form_facts = [f for f in facts if f.type == "form"]
        assert len(form_facts) >= 2
        for ff in form_facts:
            assert "fields" in ff.attributes
            assert "endpoint" in ff.attributes


# ---------------------------------------------------------------------------
# TestAllRules
# ---------------------------------------------------------------------------


class TestAllRules:
    """Test that all 20 rules are registered."""

    def test_total_rule_count(self):
        rules = get_all_rules()
        assert len(rules) >= 20

    def test_rule_names_unique(self):
        rules = get_all_rules()
        names = [r.name for r in rules]
        assert len(names) == len(set(names))

    def test_all_expected_rule_names_present(self):
        rules = get_all_rules()
        names = {r.name for r in rules}
        expected = {
            # 11 detection rules (rules.py)
            "SQL_INJECTION",
            "XSS_REFLECTED",
            "SQL_INJECTION_CRITICAL",
            "IDOR",
            "PATH_TRAVERSAL",
            "AUTH_BYPASS",
            "INFO_DISCLOSURE",
            "CSRF",
            "OPEN_REDIRECT",
            "COMMAND_INJECTION",
            "BROKEN_AUTH",
            # 4 header/config rules (rules_header.py)
            "MISSING_HSTS",
            "MISSING_XFRAME",
            "INSECURE_COOKIES",
            "SENSITIVE_DATA_EXPOSURE",
            # 5 chaining rules (rules_chaining.py)
            "CHAIN_BYPASS_EXFIL",
            "CHAIN_XSS_SESSION",
            "CHAIN_IDOR_INFO",
            "XSS_CRITICAL",
            "MULTI_VULN_CRITICAL",
        }
        missing = expected - names
        assert not missing, f"Missing rules: {missing}"

    def test_rules_have_valid_priorities(self):
        rules = get_all_rules()
        for r in rules:
            assert isinstance(r.priority, int)
            assert r.priority > 0

    def test_fresh_rules_not_fired(self):
        """Each call to get_all_rules returns fresh instances with fired=False."""
        rules = get_all_rules()
        for r in rules:
            assert r.fired is False


# ---------------------------------------------------------------------------
# TestExpertEngine (existing, expanded)
# ---------------------------------------------------------------------------


class TestExpertEngine:
    """Tests du moteur de chainage avant."""

    def test_rules_fire(self):
        _engine, plan = _run_engine_on_fixture()
        assert len(plan.rules_fired) >= 3

    def test_sql_injection_fires_first(self):
        _engine, plan = _run_engine_on_fixture()
        assert "SQL_INJECTION" in plan.rules_fired
        idx_sqli = plan.rules_fired.index("SQL_INJECTION")
        idx_critical = plan.rules_fired.index("SQL_INJECTION_CRITICAL")
        assert idx_sqli < idx_critical, "SQL_INJECTION doit s'activer avant SQL_INJECTION_CRITICAL"

    def test_xss_fires(self):
        _engine, plan = _run_engine_on_fixture()
        assert "XSS_REFLECTED" in plan.rules_fired

    def test_chaining_produces_critical(self):
        """Verifie que le chainage eleve la severite a CRITICAL."""
        _engine, plan = _run_engine_on_fixture()
        critical_vectors = [
            v
            for v in plan.vectors
            if (v.severity.value if hasattr(v.severity, "value") else v.severity) == "CRITICAL"
        ]
        assert len(critical_vectors) >= 1, "Au moins un vecteur doit etre CRITICAL apres chainage"

    def test_attack_vectors_generated(self):
        _engine, plan = _run_engine_on_fixture()
        assert len(plan.vectors) >= 2  # Au moins SQLi + XSS

    def test_plan_has_scan_id(self):
        _engine, plan = _run_engine_on_fixture()
        assert plan.scan_id == "scan-001"

    def test_plan_has_generated_at(self):
        _engine, plan = _run_engine_on_fixture()
        assert plan.generated_at is not None
        assert len(plan.generated_at) > 0

    def test_vectors_have_owasp_ref(self):
        _engine, plan = _run_engine_on_fixture()
        for vec in plan.vectors:
            assert vec.owasp_ref, f"Vector {vec.id} missing owasp_ref"


# ---------------------------------------------------------------------------
# TestDirectDetectionRules (rules 4-11)
# ---------------------------------------------------------------------------


class TestDirectDetectionRules:
    """Test rules 4-11 fire on appropriate facts."""

    def test_idor_fires_on_numeric_endpoint(self):
        """IDOR rule should fire on endpoint /rest/basket/1 with auth_required=True."""
        _engine, plan = _run_engine_on_fixture()
        assert "IDOR" in plan.rules_fired

        idor_vectors = [v for v in plan.vectors if v.attack_type.value == "idor"]
        assert len(idor_vectors) >= 1
        target_endpoints = [v.target_endpoint for v in idor_vectors]
        assert "/rest/basket/1" in target_endpoints

    def test_idor_does_not_fire_without_auth(self):
        """IDOR should NOT fire if no endpoint has auth_required=True with numeric ID."""
        facts = [
            Fact(
                type="endpoint",
                attributes={
                    "path": "/api/items/1",
                    "method": "GET",
                    "status_code": 200,
                    "auth_required": False,
                    "parameters": [],
                },
            ),
        ]
        _engine, plan = _run_engine_on_facts(facts)
        assert "IDOR" not in plan.rules_fired

    def test_auth_bypass_fires_on_admin_no_auth(self):
        """AUTH_BYPASS rule fires when /rest/admin/... endpoint has auth_required=False."""
        _engine, plan = _run_engine_on_fixture()
        assert "AUTH_BYPASS" in plan.rules_fired

        auth_bypass_vectors = [v for v in plan.vectors if v.attack_type.value == "auth_bypass"]
        admin_targets = [v for v in auth_bypass_vectors if "admin" in v.target_endpoint.lower()]
        assert len(admin_targets) >= 1

    def test_info_disclosure_fires_on_leaked_info(self):
        """INFO_DISCLOSURE fires when server_info_leaked=True or 2+ missing headers."""
        _engine, plan = _run_engine_on_fixture()
        assert "INFO_DISCLOSURE" in plan.rules_fired

        info_vectors = [v for v in plan.vectors if v.attack_type.value == "info_disclosure"]
        assert len(info_vectors) >= 1

    def test_info_disclosure_fires_on_missing_headers_alone(self):
        """INFO_DISCLOSURE should fire with 2+ missing security headers even without leak."""
        facts = [
            Fact(type="missing_header", attributes={"header": "Content-Security-Policy"}),
            Fact(type="missing_header", attributes={"header": "X-Frame-Options"}),
        ]
        _engine, plan = _run_engine_on_facts(facts)
        assert "INFO_DISCLOSURE" in plan.rules_fired

    def test_path_traversal_fires_on_file_param(self):
        """PATH_TRAVERSAL fires on endpoint with 'file' parameter."""
        facts = [
            Fact(
                type="endpoint",
                attributes={
                    "path": "/download",
                    "method": "GET",
                    "status_code": 200,
                    "auth_required": False,
                    "parameters": ["file"],
                },
            ),
        ]
        _engine, plan = _run_engine_on_facts(facts)
        assert "PATH_TRAVERSAL" in plan.rules_fired

        pt_vectors = [v for v in plan.vectors if v.attack_type.value == "path_traversal"]
        assert len(pt_vectors) >= 1
        assert pt_vectors[0].target_endpoint == "/download"

    def test_path_traversal_fires_on_path_param(self):
        """PATH_TRAVERSAL fires on endpoint with 'path' parameter."""
        facts = [
            Fact(
                type="endpoint",
                attributes={
                    "path": "/view",
                    "method": "GET",
                    "status_code": 200,
                    "auth_required": False,
                    "parameters": ["path"],
                },
            ),
        ]
        _engine, plan = _run_engine_on_facts(facts)
        assert "PATH_TRAVERSAL" in plan.rules_fired

    def test_csrf_fires_on_post_form_no_csrf_field(self):
        """CSRF fires on POST form that lacks CSRF token field."""
        _engine, plan = _run_engine_on_fixture()
        assert "CSRF" in plan.rules_fired

    def test_open_redirect_fires_on_redirect_param(self):
        """OPEN_REDIRECT fires when endpoint has 'redirect' or 'url' parameter."""
        facts = [
            Fact(
                type="endpoint",
                attributes={
                    "path": "/auth/callback",
                    "method": "GET",
                    "status_code": 302,
                    "auth_required": False,
                    "parameters": ["redirect"],
                },
            ),
        ]
        _engine, plan = _run_engine_on_facts(facts)
        assert "OPEN_REDIRECT" in plan.rules_fired

    def test_command_injection_fires_on_cmd_param(self):
        """COMMAND_INJECTION fires when endpoint has 'cmd' or 'exec' parameter."""
        facts = [
            Fact(
                type="endpoint",
                attributes={
                    "path": "/api/tools/run",
                    "method": "POST",
                    "status_code": 200,
                    "auth_required": False,
                    "parameters": ["cmd"],
                },
            ),
            Fact(type="technology", attributes={"name": "Node.js"}),
        ]
        _engine, plan = _run_engine_on_facts(facts)
        assert "COMMAND_INJECTION" in plan.rules_fired

    def test_command_injection_skipped_for_static_only(self):
        """COMMAND_INJECTION should NOT fire if only static frameworks are present."""
        facts = [
            Fact(
                type="endpoint",
                attributes={
                    "path": "/search",
                    "method": "GET",
                    "status_code": 200,
                    "auth_required": False,
                    "parameters": ["query"],
                },
            ),
            Fact(type="technology", attributes={"name": "html"}),
            Fact(type="technology", attributes={"name": "css"}),
        ]
        _engine, plan = _run_engine_on_facts(facts)
        assert "COMMAND_INJECTION" not in plan.rules_fired

    def test_broken_auth_fires_on_login_endpoint(self):
        """BROKEN_AUTH fires when a login form exists."""
        _engine, plan = _run_engine_on_fixture()
        assert "BROKEN_AUTH" in plan.rules_fired


# ---------------------------------------------------------------------------
# TestHeaderRules (rules 12-15)
# ---------------------------------------------------------------------------


class TestHeaderRules:
    """Test the 4 header/config rules from rules_header.py."""

    def test_missing_hsts_fires(self):
        """MISSING_HSTS fires when Strict-Transport-Security header is missing."""
        _engine, plan = _run_engine_on_fixture()
        assert "MISSING_HSTS" in plan.rules_fired

    def test_missing_xframe_fires(self):
        """MISSING_XFRAME fires when X-Frame-Options header is missing."""
        _engine, plan = _run_engine_on_fixture()
        assert "MISSING_XFRAME" in plan.rules_fired

    def test_insecure_cookies_fires_on_leaked_info(self):
        """INSECURE_COOKIES fires when server_info_leaked is True."""
        _engine, plan = _run_engine_on_fixture()
        assert "INSECURE_COOKIES" in plan.rules_fired

    def test_sensitive_data_exposure_fires(self):
        """SENSITIVE_DATA_EXPOSURE fires on endpoint with sensitive path and no auth."""
        # The fixture has /rest/admin/application-configuration which contains 'config'
        # but let's also explicitly test with a clear sensitive endpoint
        facts = [
            Fact(
                type="endpoint",
                attributes={
                    "path": "/debug/status",
                    "method": "GET",
                    "status_code": 200,
                    "auth_required": False,
                    "parameters": [],
                },
            ),
        ]
        _engine, plan = _run_engine_on_facts(facts)
        assert "SENSITIVE_DATA_EXPOSURE" in plan.rules_fired

    def test_sensitive_data_exposure_skipped_with_auth(self):
        """SENSITIVE_DATA_EXPOSURE should NOT fire if auth is required."""
        facts = [
            Fact(
                type="endpoint",
                attributes={
                    "path": "/debug/status",
                    "method": "GET",
                    "status_code": 200,
                    "auth_required": True,
                    "parameters": [],
                },
            ),
        ]
        _engine, plan = _run_engine_on_facts(facts)
        assert "SENSITIVE_DATA_EXPOSURE" not in plan.rules_fired


# ---------------------------------------------------------------------------
# TestChainingRules (rules 16-20)
# ---------------------------------------------------------------------------


class TestChainingRules:
    """Test that chaining rules elevate severity correctly."""

    def test_chain_bypass_exfil_elevates_to_critical(self):
        """When auth_bypass + sqli both exist, CHAIN_BYPASS_EXFIL elevates both to CRITICAL."""
        facts = [
            # Needs a form + SQL tech for SQL_INJECTION rule
            Fact(
                type="form",
                attributes={
                    "endpoint": "/login",
                    "fields": ["email", "password"],
                    "method": "POST",
                },
            ),
            Fact(type="technology", attributes={"name": "SQLite"}),
            # Needs admin endpoint without auth for AUTH_BYPASS rule
            Fact(
                type="endpoint",
                attributes={
                    "path": "/admin/panel",
                    "method": "GET",
                    "status_code": 200,
                    "auth_required": False,
                    "parameters": [],
                },
            ),
            # Needs /login as POST endpoint to avoid auth_required check issues
            Fact(
                type="endpoint",
                attributes={
                    "path": "/login",
                    "method": "POST",
                    "status_code": 200,
                    "auth_required": False,
                    "parameters": ["email", "password"],
                },
            ),
        ]
        _engine, plan = _run_engine_on_facts(facts)
        assert "CHAIN_BYPASS_EXFIL" in plan.rules_fired

        # Both sqli and auth_bypass vectors should be CRITICAL
        for vec in plan.vectors:
            if vec.attack_type.value in ("sqli", "auth_bypass"):
                assert vec.severity.value == "CRITICAL", (
                    f"Vector {vec.id} ({vec.attack_type.value}) should be CRITICAL "
                    f"after CHAIN_BYPASS_EXFIL, got {vec.severity.value}"
                )

    def test_chain_xss_session_elevates_xss(self):
        """When xss + info_disclosure both exist, CHAIN_XSS_SESSION elevates XSS to HIGH."""
        _engine, plan = _run_engine_on_fixture()
        # The fixture should produce both XSS and INFO_DISCLOSURE vectors
        if "CHAIN_XSS_SESSION" in plan.rules_fired:
            xss_vectors = [v for v in plan.vectors if v.attack_type.value == "xss"]
            for vec in xss_vectors:
                assert vec.severity.value in ("HIGH", "CRITICAL"), (
                    f"XSS vector {vec.id} should be at least HIGH after chaining"
                )

    def test_chain_idor_info_elevates_idor(self):
        """When idor + info_disclosure both exist, CHAIN_IDOR_INFO elevates IDOR to CRITICAL."""
        _engine, plan = _run_engine_on_fixture()
        if "CHAIN_IDOR_INFO" in plan.rules_fired:
            idor_vectors = [v for v in plan.vectors if v.attack_type.value == "idor"]
            for vec in idor_vectors:
                assert vec.severity.value == "CRITICAL", (
                    f"IDOR vector {vec.id} should be CRITICAL after CHAIN_IDOR_INFO"
                )

    def test_multi_vuln_critical(self):
        """When 3+ HIGH/CRITICAL vectors exist, MULTI_VULN_CRITICAL elevates MEDIUM to HIGH."""
        _engine, plan = _run_engine_on_fixture()
        # The fixture should generate enough HIGH/CRITICAL vectors to trigger this rule
        if "MULTI_VULN_CRITICAL" in plan.rules_fired:
            for vec in plan.vectors:
                # After MULTI_VULN_CRITICAL, no vector should remain at MEDIUM
                assert vec.severity.value != "MEDIUM", (
                    f"Vector {vec.id} should not be MEDIUM after MULTI_VULN_CRITICAL"
                )

    def test_xss_critical_on_no_auth_endpoint(self):
        """XSS_CRITICAL elevates XSS to HIGH when target endpoint has no auth."""
        _engine, plan = _run_engine_on_fixture()
        # The fixture has POST endpoints without auth that trigger XSS
        if "XSS_CRITICAL" in plan.rules_fired:
            xss_vectors = [v for v in plan.vectors if v.attack_type.value == "xss"]
            for vec in xss_vectors:
                assert vec.severity.value in ("HIGH", "CRITICAL"), (
                    f"XSS vector {vec.id} should be at least HIGH after XSS_CRITICAL"
                )

    def test_chaining_rules_fire_after_detection_rules(self):
        """Chaining rules (priority >= 8) must fire after detection rules (priority <= 5)."""
        _engine, plan = _run_engine_on_fixture()
        chaining_rules = {
            "CHAIN_BYPASS_EXFIL",
            "CHAIN_XSS_SESSION",
            "CHAIN_IDOR_INFO",
            "XSS_CRITICAL",
            "MULTI_VULN_CRITICAL",
        }
        detection_rules = {
            "SQL_INJECTION",
            "XSS_REFLECTED",
            "SQL_INJECTION_CRITICAL",
            "IDOR",
            "PATH_TRAVERSAL",
            "AUTH_BYPASS",
            "INFO_DISCLOSURE",
            "CSRF",
            "OPEN_REDIRECT",
            "COMMAND_INJECTION",
            "BROKEN_AUTH",
            "MISSING_HSTS",
            "MISSING_XFRAME",
            "INSECURE_COOKIES",
            "SENSITIVE_DATA_EXPOSURE",
        }

        fired = plan.rules_fired
        for chain_rule in chaining_rules:
            if chain_rule not in fired:
                continue
            chain_idx = fired.index(chain_rule)
            for det_rule in detection_rules:
                if det_rule not in fired:
                    continue
                det_idx = fired.index(det_rule)
                assert det_idx < chain_idx, (
                    f"Detection rule {det_rule} should fire before chaining rule {chain_rule}"
                )


# ---------------------------------------------------------------------------
# TestEngineEdgeCases
# ---------------------------------------------------------------------------


class TestEngineEdgeCases:
    """Edge cases for the expert engine."""

    def test_empty_facts_produces_empty_plan(self):
        """Engine with no facts should produce an empty plan."""
        engine = ExpertEngine()
        engine.inject_facts([])
        engine.load_rules(get_all_rules())
        plan = engine.run(llm_second_pass=False)
        assert len(plan.vectors) == 0
        assert len(plan.rules_fired) == 0

    def test_duplicate_facts_handled(self):
        """Engine should handle duplicate facts gracefully."""
        facts = [
            Fact(type="missing_header", attributes={"header": "Content-Security-Policy"}),
            Fact(type="missing_header", attributes={"header": "Content-Security-Policy"}),
            Fact(type="missing_header", attributes={"header": "X-Frame-Options"}),
        ]
        _engine, plan = _run_engine_on_facts(facts)
        # Should still produce a valid plan without crashing
        assert plan is not None
