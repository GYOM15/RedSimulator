"""End-to-end pipeline test using fixtures."""

import json
from pathlib import Path


class TestPipelineE2E:
    """Run the full pipeline with fixtures and verify each stage."""

    def _load_fixture(self, name):
        path = Path(__file__).parent.parent / "data" / "fixtures" / name
        return json.loads(path.read_text())

    def test_full_pipeline_fixtures(self):
        """Run scanner->expert->generator->executor->reporter with fixtures."""
        from src.models import ScanResult

        # Stage 1: Load scan fixture
        scan = ScanResult.model_validate(self._load_fixture("scan_result.json"))
        assert len(scan.endpoints) > 0

        # Stage 2: Expert system
        from src.expert import ExpertEngine, get_all_rules, scan_result_to_facts

        facts = scan_result_to_facts(scan)
        engine = ExpertEngine()
        engine.inject_facts(facts)
        engine.load_rules(get_all_rules())
        plan = engine.run(scan=scan, llm_second_pass=False)
        assert len(plan.vectors) > 0
        assert len(engine.fired_rules) >= 10  # At least 10 rules should fire

        # Stage 3: Generator
        from src.generator import generate_for_plan

        payload_result = generate_for_plan(plan)
        assert len(payload_result.payloads) > 0
        # Each vector should have at least some variants
        for gp in payload_result.payloads:
            assert len(gp.variants) >= 1

        # Stage 4: Executor (from fixtures since we need a live target)
        from src.executor import AttackExecutor

        attack_result = AttackExecutor.from_fixtures()
        assert attack_result.total_attempts > 0

        # Stage 5: Reporter
        from src.reporter import generate_report

        report = generate_report(scan, plan, attack_result)
        assert len(report) > 100
        assert (
            "RedSimulator" in report
            or "Securite" in report.lower()
            or "vulnerabilit" in report.lower()
        )

        # Stage 6: RAG indexing
        from src.reporter.rag import index_report

        num_chunks = index_report(report, scan=scan, plan=plan, results=attack_result)
        assert num_chunks > 0

    def test_pipeline_produces_critical_findings(self):
        """Verify the pipeline detects CRITICAL vulnerabilities on Juice Shop."""
        from src.expert import ExpertEngine, get_all_rules, scan_result_to_facts
        from src.models import ScanResult

        scan = ScanResult.model_validate(self._load_fixture("scan_result.json"))
        facts = scan_result_to_facts(scan)
        engine = ExpertEngine()
        engine.inject_facts(facts)
        engine.load_rules(get_all_rules())
        plan = engine.run(scan=scan, llm_second_pass=False)

        severities = [v.severity.value for v in plan.vectors]
        assert "CRITICAL" in severities, "Pipeline should detect CRITICAL vulnerabilities"

    def test_pipeline_covers_multiple_attack_types(self):
        """Verify the pipeline detects multiple attack types."""
        from src.expert import ExpertEngine, get_all_rules, scan_result_to_facts
        from src.models import ScanResult

        scan = ScanResult.model_validate(self._load_fixture("scan_result.json"))
        facts = scan_result_to_facts(scan)
        engine = ExpertEngine()
        engine.inject_facts(facts)
        engine.load_rules(get_all_rules())
        plan = engine.run(scan=scan, llm_second_pass=False)

        attack_types = {v.attack_type.value for v in plan.vectors}
        assert len(attack_types) >= 3, f"Should detect 3+ attack types, found: {attack_types}"

    def test_knowledge_graph_builds(self):
        """Verify knowledge graph builds from pipeline results."""
        from src.models import AttackPlan, AttackResult, ScanResult
        from src.reporter.rag.knowledge_graph import KnowledgeGraph

        scan = ScanResult.model_validate(self._load_fixture("scan_result.json"))
        plan = AttackPlan.model_validate(self._load_fixture("attack_plan.json"))
        results = AttackResult.model_validate(self._load_fixture("attack_result.json"))

        kg = KnowledgeGraph()
        kg.build(scan, plan, results)
        # Graph should have nodes and edges
        assert kg.graph.number_of_nodes() > 0
        assert kg.graph.number_of_edges() > 0

        # Query should return results
        kg.query_by_severity("CRITICAL")
        # The fixture should have at least one CRITICAL vector
