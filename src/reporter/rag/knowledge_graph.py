"""Knowledge graph module for the RedSimulator RAG system.

Builds a directed graph from scan results, attack plan, and execution results
using NetworkX.  The graph enables structured queries alongside vector search,
answering questions like "What vulnerabilities affect the login endpoint?" or
"Show the attack chain for data exfiltration."

Node types:
    vulnerability, endpoint, technology, header, form, remediation,
    owasp_category, result

Edge types (relationships):
    TARGETS, EXPLOITS, USES_TECH, MAPS_TO, FIXED_BY, CHAINS_WITH,
    RUNS_ON, AFFECTS, RESULT
"""

from __future__ import annotations

import re
from typing import Any

from src.infra.decorators import logged, timed
from src.infra.logging import get_logger
from src.models import (
    AttackPlan,
    AttackResult,
    AttackVector,
    ScanResult,
)

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Try importing NetworkX; degrade gracefully if missing.
# ---------------------------------------------------------------------------

try:
    import networkx as nx
except ImportError:  # pragma: no cover
    nx = None  # type: ignore[assignment]
    logger.warning(
        "networkx is not installed -- KnowledgeGraph will operate in "
        "no-op mode.  Install it with: pip install networkx"
    )

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) mapping
# ---------------------------------------------------------------------------

OWASP_CATEGORIES: dict[str, tuple[str, str]] = {
    "sqli": ("A03:2021", "Injection"),
    "xss": ("A03:2021", "Injection"),
    "idor": ("A01:2021", "Broken Access Control"),
    "path_traversal": ("A01:2021", "Broken Access Control"),
    "auth_bypass": ("A07:2021", "Identification and Authentication Failures"),
    "info_disclosure": ("A05:2021", "Security Misconfiguration"),
    "command_injection": ("A03:2021", "Injection"),
    "csrf": ("A01:2021", "Broken Access Control"),
    "open_redirect": ("A01:2021", "Broken Access Control"),
}

# ---------------------------------------------------------------------------
# Remediation templates
# ---------------------------------------------------------------------------

_REMEDIATION_TEMPLATES: dict[str, str] = {
    "sqli": "Implement prepared statements and parameterized queries",
    "xss": "Apply output encoding and implement Content-Security-Policy",
    "idor": "Enforce server-side authorization checks on every object access",
    "path_traversal": "Validate and canonicalize file paths; use allowlists",
    "auth_bypass": "Strengthen authentication controls and session management",
    "info_disclosure": "Remove verbose error messages and server banners",
    "command_injection": "Avoid shell commands; use safe APIs with input validation",
    "csrf": "Implement anti-CSRF tokens on all state-changing requests",
    "open_redirect": "Validate redirect targets against an allowlist of trusted URLs",
}

# Severity ordering for comparisons (higher index = more severe).
_SEVERITY_ORDER: dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def _severity_gte(severity: str, threshold: str) -> bool:
    """Return True if *severity* is >= *threshold*."""
    return _SEVERITY_ORDER.get(severity.upper(), 0) >= _SEVERITY_ORDER.get(threshold.upper(), 0)


def _priority_from_severity(severity: str) -> str:
    """Map a vulnerability severity to a remediation priority label."""
    mapping = {
        "CRITICAL": "P0 - Immediate",
        "HIGH": "P1 - High",
        "MEDIUM": "P2 - Medium",
        "LOW": "P3 - Low",
    }
    return mapping.get(severity.upper(), "P3 - Low")


# ---------------------------------------------------------------------------
# KnowledgeGraph
# ---------------------------------------------------------------------------


class KnowledgeGraph:
    """Security assessment knowledge graph built from pipeline results.

    The graph uses :pymod:`networkx` under the hood.  If NetworkX is not
    installed every public method degrades gracefully (returns empty results
    and logs a warning).
    """

    def __init__(self) -> None:
        if nx is not None:
            self.graph: Any = nx.DiGraph()
        else:
            self.graph = None

    # -- helpers -------------------------------------------------------------

    def _noop_check(self) -> bool:
        """Return True if the graph backend is unavailable."""
        if self.graph is None:
            logger.warning("KnowledgeGraph: networkx not available, returning empty result")
            return True
        return False

    def _add_node(self, node_id: str, **attrs: Any) -> None:
        self.graph.add_node(node_id, **attrs)

    def _add_edge(self, src: str, dst: str, **attrs: Any) -> None:
        self.graph.add_edge(src, dst, **attrs)

    # -- build methods -------------------------------------------------------

    @logged
    @timed
    def build(
        self,
        scan: ScanResult,
        plan: AttackPlan,
        results: AttackResult,
    ) -> None:
        """Build the knowledge graph from pipeline results."""
        if self._noop_check():
            return

        self._add_endpoints(scan)
        self._add_technologies(scan)
        self._add_headers(scan)
        self._add_forms(scan)
        self._add_owasp_categories()
        self._add_vulnerabilities(plan)
        self._add_results(results)
        self._add_chains(plan)
        self._add_remediations(plan)

        logger.info(
            "Knowledge graph built: %d nodes, %d edges",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )

    # -- private builders ----------------------------------------------------

    def _add_endpoints(self, scan: ScanResult) -> None:
        for ep in scan.endpoints:
            node_id = f"endpoint:{ep.method}:{ep.path}"
            self._add_node(
                node_id,
                node_type="endpoint",
                path=ep.path,
                method=ep.method,
                status_code=ep.status_code,
                auth_required=ep.auth_required,
                parameters=ep.parameters,
            )

    def _add_technologies(self, scan: ScanResult) -> None:
        for tech in scan.technologies:
            node_id = f"tech:{tech}"
            self._add_node(node_id, node_type="technology", name=tech)
            # Link technologies to every endpoint (they run on the same stack).
            for ep in scan.endpoints:
                ep_id = f"endpoint:{ep.method}:{ep.path}"
                self._add_edge(ep_id, node_id, relationship="RUNS_ON")

    def _add_headers(self, scan: ScanResult) -> None:
        for header_name in scan.headers.missing_security_headers:
            h_id = f"header:{header_name}"
            self._add_node(
                h_id,
                node_type="header",
                name=header_name,
                status="missing",
            )
            # A missing header affects every discovered endpoint.
            for ep in scan.endpoints:
                ep_id = f"endpoint:{ep.method}:{ep.path}"
                self._add_edge(h_id, ep_id, relationship="AFFECTS")

    def _add_forms(self, scan: ScanResult) -> None:
        for idx, form in enumerate(scan.forms):
            form_id = f"form:{idx}:{form.endpoint}"
            field_names = [f.name for f in form.fields] if form.fields else []
            self._add_node(
                form_id,
                node_type="form",
                endpoint=form.endpoint,
                method=form.method,
                fields=field_names,
                action=form.action,
            )

    def _add_owasp_categories(self) -> None:
        added: set[str] = set()
        for owasp_id, owasp_name in OWASP_CATEGORIES.values():
            if owasp_id not in added:
                self._add_node(
                    f"owasp:{owasp_id}",
                    node_type="owasp_category",
                    id=owasp_id,
                    name=owasp_name,
                )
                added.add(owasp_id)

    def _add_vulnerabilities(self, plan: AttackPlan) -> None:
        for vec in plan.vectors:
            v_id = f"vuln:{vec.id}"
            self._add_node(
                v_id,
                node_type="vulnerability",
                id=vec.id,
                attack_type=str(vec.attack_type),
                severity=str(vec.severity),
                owasp_ref=vec.owasp_ref,
                target_endpoint=vec.target_endpoint,
                target_fields=vec.target_fields,
                rationale=vec.rationale,
            )

            # TARGETS -> endpoint
            for method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                ep_id = f"endpoint:{method}:{vec.target_endpoint}"
                if self.graph.has_node(ep_id):
                    self._add_edge(v_id, ep_id, relationship="TARGETS")

            # EXPLOITS -> form (match by endpoint)
            for node_id, data in list(self.graph.nodes(data=True)):
                if data.get("node_type") == "form" and data.get("endpoint") == vec.target_endpoint:
                    self._add_edge(v_id, node_id, relationship="EXPLOITS")

            # USES_TECH -> technology (link every vuln to discovered techs)
            for node_id, data in list(self.graph.nodes(data=True)):
                if data.get("node_type") == "technology":
                    self._add_edge(v_id, node_id, relationship="USES_TECH")

            # MAPS_TO -> owasp_category
            attack_key = str(vec.attack_type)
            if attack_key in OWASP_CATEGORIES:
                owasp_id, _ = OWASP_CATEGORIES[attack_key]
                self._add_edge(v_id, f"owasp:{owasp_id}", relationship="MAPS_TO")

    def _add_results(self, results: AttackResult) -> None:
        for idx, res in enumerate(results.results):
            r_id = f"result:{idx}:{res.vector_id}"
            self._add_node(
                r_id,
                node_type="result",
                vector_id=res.vector_id,
                payload_used=res.payload_used,
                target_endpoint=res.target_endpoint,
                http_status=res.http_status,
                response_snippet=res.response_snippet,
                success=res.success,
                detection_method=res.detection_method,
            )
            # Link result back to its vulnerability vector.
            v_id = f"vuln:{res.vector_id}"
            if self.graph.has_node(v_id):
                self._add_edge(v_id, r_id, relationship="RESULT")

    def _add_chains(self, plan: AttackPlan) -> None:
        """Add CHAINS_WITH edges between vulnerability vectors.

        Chaining heuristics:
        1. info_disclosure -> any higher-severity vuln on the same endpoint.
        2. auth_bypass -> any vuln that targets an auth-required endpoint.
        3. xss / csrf -> sqli on the same endpoint (client-side to server-side).
        """
        vectors_by_endpoint: dict[str, list[AttackVector]] = {}
        for vec in plan.vectors:
            vectors_by_endpoint.setdefault(vec.target_endpoint, []).append(vec)

        for _endpoint, vecs in vectors_by_endpoint.items():
            for v1 in vecs:
                for v2 in vecs:
                    if v1.id == v2.id:
                        continue
                    chain = False

                    # info_disclosure feeds into higher-severity attacks
                    if str(v1.attack_type) == "info_disclosure" and _severity_gte(
                        str(v2.severity), "MEDIUM"
                    ):
                        chain = True

                    # auth_bypass enables attacks behind auth walls
                    if str(v1.attack_type) == "auth_bypass":
                        chain = True

                    # XSS/CSRF can chain into SQLi
                    if str(v1.attack_type) in ("xss", "csrf") and str(v2.attack_type) == "sqli":
                        chain = True

                    if chain:
                        self._add_edge(
                            f"vuln:{v1.id}",
                            f"vuln:{v2.id}",
                            relationship="CHAINS_WITH",
                        )

    def _add_remediations(self, plan: AttackPlan) -> None:
        """Create remediation nodes linked to vulnerability nodes."""
        # Track remediations per attack type to avoid duplicates.
        created: dict[str, str] = {}  # attack_type -> remediation node id
        for vec in plan.vectors:
            attack_key = str(vec.attack_type)
            if attack_key not in created:
                title = _REMEDIATION_TEMPLATES.get(
                    attack_key, f"Review and remediate {attack_key} vulnerabilities"
                )
                priority = _priority_from_severity(str(vec.severity))
                rem_id = f"remediation:{attack_key}"
                self._add_node(
                    rem_id,
                    node_type="remediation",
                    title=title,
                    priority=priority,
                    attack_type=attack_key,
                )
                created[attack_key] = rem_id
            else:
                # Escalate priority if a higher-severity vector appears.
                rem_id = created[attack_key]
                existing_priority = self.graph.nodes[rem_id].get("priority", "")
                new_priority = _priority_from_severity(str(vec.severity))
                if new_priority < existing_priority:  # P0 < P1 lexicographically
                    self.graph.nodes[rem_id]["priority"] = new_priority

            self._add_edge(f"vuln:{vec.id}", rem_id, relationship="FIXED_BY")

    # ======================================================================
    # Query methods
    # ======================================================================

    def query_by_endpoint(self, path: str) -> list[dict]:
        """Find all vulnerabilities targeting a specific endpoint."""
        if self._noop_check():
            return []

        results: list[dict] = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get("node_type") == "vulnerability" and data.get("target_endpoint") == path:
                results.append({"node_id": node_id, **data})
        return results

    def query_by_severity(self, severity: str) -> list[dict]:
        """Find all vulnerabilities of a given severity."""
        if self._noop_check():
            return []

        severity_upper = severity.upper()
        results: list[dict] = []
        for node_id, data in self.graph.nodes(data=True):
            if (
                data.get("node_type") == "vulnerability"
                and data.get("severity", "").upper() == severity_upper
            ):
                results.append({"node_id": node_id, **data})
        return results

    def query_by_attack_type(self, attack_type: str) -> list[dict]:
        """Find all vulnerabilities of a given type."""
        if self._noop_check():
            return []

        results: list[dict] = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get("node_type") == "vulnerability" and data.get("attack_type") == attack_type:
                results.append({"node_id": node_id, **data})
        return results

    def query_attack_chains(self) -> list[list[dict]]:
        """Find chains of vulnerabilities (connected via CHAINS_WITH).

        Returns a list of chains, where each chain is a list of
        vulnerability dicts ordered from the initial attack step to the
        final exploitation step.
        """
        if self._noop_check():
            return []

        # Build a subgraph containing only CHAINS_WITH edges.
        chain_edges = [
            (u, v)
            for u, v, d in self.graph.edges(data=True)
            if d.get("relationship") == "CHAINS_WITH"
        ]
        if not chain_edges:
            return []

        subgraph = self.graph.edge_subgraph(chain_edges)
        chains: list[list[dict]] = []

        # Find weakly connected components -- each is a potential chain.
        for component in nx.weakly_connected_components(subgraph):
            comp_sub = subgraph.subgraph(component)
            # Find source nodes (no in-edges within the component).
            sources = [n for n in comp_sub if comp_sub.in_degree(n) == 0]
            if not sources:
                # Cycle -- pick any node.
                sources = [next(iter(component))]

            for source in sources:
                # Walk all simple paths from this source.
                sinks = [n for n in comp_sub if comp_sub.out_degree(n) == 0]
                if not sinks:
                    sinks = [n for n in component if n != source]
                for sink in sinks:
                    for path in nx.all_simple_paths(comp_sub, source, sink):
                        chain = [{"node_id": n, **self.graph.nodes[n]} for n in path]
                        chains.append(chain)

        return chains

    def query_remediations(self, severity_min: str = "MEDIUM") -> list[dict]:
        """Get prioritized remediations for vulnerabilities above a severity threshold."""
        if self._noop_check():
            return []

        remediations: list[dict] = []
        seen_rem_ids: set[str] = set()

        for node_id, data in self.graph.nodes(data=True):
            if data.get("node_type") != "vulnerability":
                continue
            if not _severity_gte(data.get("severity", "LOW"), severity_min):
                continue

            # Find linked remediations.
            for _, neighbor in self.graph.out_edges(node_id):
                edge_data = self.graph.edges[node_id, neighbor]
                if edge_data.get("relationship") == "FIXED_BY" and neighbor not in seen_rem_ids:
                    seen_rem_ids.add(neighbor)
                    rem_data = dict(self.graph.nodes[neighbor])
                    rem_data["node_id"] = neighbor
                    # Attach the list of vulnerability IDs this fixes.
                    linked_vulns = [
                        src
                        for src, dst, ed in self.graph.in_edges(neighbor, data=True)
                        if ed.get("relationship") == "FIXED_BY"
                    ]
                    rem_data["fixes_vulnerabilities"] = linked_vulns
                    remediations.append(rem_data)

        # Sort by priority (P0 first).
        remediations.sort(key=lambda r: r.get("priority", "P9"))
        return remediations

    def query_endpoint_risk(self, path: str) -> dict:
        """Get a risk summary for a specific endpoint.

        Returns a dict with:
        - path: the endpoint path
        - vulnerabilities: list of vulnerability summaries
        - severity_counts: count per severity level
        - technologies: list of technology names running on the endpoint
        - missing_headers: list of missing security headers affecting it
        - successful_attacks: count of successful attack results
        """
        if self._noop_check():
            return {}

        vulns = self.query_by_endpoint(path)
        severity_counts: dict[str, int] = {}
        successful_attacks = 0

        for v in vulns:
            sev = v.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Count successful results linked to this vulnerability.
            v_node = v.get("node_id", "")
            if self.graph.has_node(v_node):
                for _, neighbor in self.graph.out_edges(v_node):
                    edge_data = self.graph.edges[v_node, neighbor]
                    if edge_data.get("relationship") == "RESULT" and self.graph.nodes[neighbor].get(
                        "success"
                    ):
                        successful_attacks += 1

        # Technologies on this endpoint.
        technologies: list[str] = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get("node_type") != "endpoint":
                continue
            if data.get("path") != path:
                continue
            for _, neighbor in self.graph.out_edges(node_id):
                edge_data = self.graph.edges[node_id, neighbor]
                if edge_data.get("relationship") == "RUNS_ON":
                    tech_name = self.graph.nodes[neighbor].get("name", "")
                    if tech_name and tech_name not in technologies:
                        technologies.append(tech_name)

        # Missing headers affecting this endpoint.
        missing_headers: list[str] = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get("node_type") != "header":
                continue
            for _, neighbor in self.graph.out_edges(node_id):
                edge_data = self.graph.edges[node_id, neighbor]
                if (
                    edge_data.get("relationship") == "AFFECTS"
                    and self.graph.nodes[neighbor].get("path") == path
                ):
                    header_name = data.get("name", "")
                    if header_name and header_name not in missing_headers:
                        missing_headers.append(header_name)

        return {
            "path": path,
            "vulnerabilities": [
                {
                    "id": v.get("id"),
                    "attack_type": v.get("attack_type"),
                    "severity": v.get("severity"),
                }
                for v in vulns
            ],
            "severity_counts": severity_counts,
            "technologies": technologies,
            "missing_headers": missing_headers,
            "successful_attacks": successful_attacks,
            "total_vulnerabilities": len(vulns),
        }

    # ======================================================================
    # RAG integration
    # ======================================================================

    def get_context_for_query(self, question: str) -> str:
        """Extract relevant graph context as text for RAG augmentation.

        Analyzes the question to determine which graph queries to run,
        then formats the results as context text that can be injected
        alongside vector search results.
        """
        if self._noop_check():
            return ""

        question_lower = question.lower()
        context_parts: list[str] = []

        # 1. Detect endpoint references (paths like /rest/... or /api/...).
        endpoint_pattern = r"(/[\w/\-\.]+)"
        endpoint_matches = re.findall(endpoint_pattern, question)
        for ep_path in endpoint_matches:
            risk = self.query_endpoint_risk(ep_path)
            if risk and risk.get("total_vulnerabilities", 0) > 0:
                context_parts.append(self._format_endpoint_risk(risk))

        # 2. Detect severity references.
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if severity.lower() in question_lower:
                vulns = self.query_by_severity(severity)
                if vulns:
                    context_parts.append(self._format_severity_results(severity, vulns))
                break  # Only match the first (highest) severity mentioned.

        # 3. Detect attack type references.
        attack_type_aliases: dict[str, str] = {
            "sql injection": "sqli",
            "sqli": "sqli",
            "xss": "xss",
            "cross-site scripting": "xss",
            "cross site scripting": "xss",
            "idor": "idor",
            "insecure direct object": "idor",
            "path traversal": "path_traversal",
            "directory traversal": "path_traversal",
            "auth bypass": "auth_bypass",
            "authentication bypass": "auth_bypass",
            "info disclosure": "info_disclosure",
            "information disclosure": "info_disclosure",
            "command injection": "command_injection",
            "rce": "command_injection",
            "csrf": "csrf",
            "cross-site request forgery": "csrf",
            "open redirect": "open_redirect",
        }
        for alias, attack_type in attack_type_aliases.items():
            if alias in question_lower:
                vulns = self.query_by_attack_type(attack_type)
                if vulns:
                    context_parts.append(self._format_attack_type_results(attack_type, vulns))
                break

        # 4. Detect remediation / fix questions.
        remediation_keywords = (
            "remediat",
            "fix",
            "mitigat",
            "recommend",
            "how to prevent",
            "how to protect",
            "solution",
            "countermeasure",
        )
        if any(kw in question_lower for kw in remediation_keywords):
            rems = self.query_remediations(severity_min="LOW")
            if rems:
                context_parts.append(self._format_remediations(rems))

        # 5. Detect chain / attack chain questions.
        chain_keywords = ("chain", "escalat", "pivot", "lateral", "sequence", "multi-step")
        if any(kw in question_lower for kw in chain_keywords):
            chains = self.query_attack_chains()
            if chains:
                context_parts.append(self._format_chains(chains))

        # 6. If nothing specific was detected, provide a general summary.
        if not context_parts:
            summary = self.to_summary()
            if summary:
                context_parts.append(summary)

        return "\n\n".join(context_parts)

    # -- formatting helpers --------------------------------------------------

    @staticmethod
    def _format_endpoint_risk(risk: dict) -> str:
        lines = [f"=== Endpoint Risk: {risk['path']} ==="]
        lines.append(f"Total vulnerabilities: {risk['total_vulnerabilities']}")
        lines.append(f"Successful attacks: {risk['successful_attacks']}")
        if risk.get("severity_counts"):
            counts = ", ".join(f"{k}: {v}" for k, v in risk["severity_counts"].items())
            lines.append(f"Severity breakdown: {counts}")
        if risk.get("technologies"):
            lines.append(f"Technologies: {', '.join(risk['technologies'])}")
        if risk.get("missing_headers"):
            lines.append(f"Missing security headers: {', '.join(risk['missing_headers'])}")
        for v in risk.get("vulnerabilities", []):
            lines.append(f"  - [{v.get('severity')}] {v.get('attack_type')} ({v.get('id')})")
        return "\n".join(lines)

    @staticmethod
    def _format_severity_results(severity: str, vulns: list[dict]) -> str:
        lines = [f"=== {severity} Severity Vulnerabilities ({len(vulns)}) ==="]
        for v in vulns:
            lines.append(f"  - {v.get('id')}: {v.get('attack_type')} on {v.get('target_endpoint')}")
        return "\n".join(lines)

    @staticmethod
    def _format_attack_type_results(attack_type: str, vulns: list[dict]) -> str:
        lines = [f"=== {attack_type} Vulnerabilities ({len(vulns)}) ==="]
        for v in vulns:
            lines.append(
                f"  - {v.get('id')} [{v.get('severity')}] on "
                f"{v.get('target_endpoint')} "
                f"(fields: {', '.join(v.get('target_fields', []))})"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_remediations(rems: list[dict]) -> str:
        lines = ["=== Remediations (prioritized) ==="]
        for r in rems:
            vuln_ids = [str(v).replace("vuln:", "") for v in r.get("fixes_vulnerabilities", [])]
            lines.append(f"  [{r.get('priority')}] {r.get('title')} (fixes: {', '.join(vuln_ids)})")
        return "\n".join(lines)

    @staticmethod
    def _format_chains(chains: list[list[dict]]) -> str:
        lines = [f"=== Attack Chains ({len(chains)}) ==="]
        for i, chain in enumerate(chains, 1):
            steps = " -> ".join(f"{v.get('id', '?')}({v.get('attack_type', '?')})" for v in chain)
            lines.append(f"  Chain {i}: {steps}")
        return "\n".join(lines)

    # ======================================================================
    # Summary
    # ======================================================================

    def to_summary(self) -> str:
        """Generate a text summary of the entire graph."""
        if self._noop_check():
            return ""

        type_counts: dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            ntype = data.get("node_type", "unknown")
            type_counts[ntype] = type_counts.get(ntype, 0) + 1

        rel_counts: dict[str, int] = {}
        for _, _, data in self.graph.edges(data=True):
            rel = data.get("relationship", "unknown")
            rel_counts[rel] = rel_counts.get(rel, 0) + 1

        lines = [
            "=== Knowledge Graph Summary ===",
            f"Total nodes: {self.graph.number_of_nodes()}",
            f"Total edges: {self.graph.number_of_edges()}",
            "",
            "Node types:",
        ]
        for ntype, count in sorted(type_counts.items()):
            lines.append(f"  {ntype}: {count}")

        lines.append("")
        lines.append("Relationship types:")
        for rel, count in sorted(rel_counts.items()):
            lines.append(f"  {rel}: {count}")

        # Severity distribution of vulnerabilities.
        severity_dist: dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            if data.get("node_type") == "vulnerability":
                sev = data.get("severity", "UNKNOWN")
                severity_dist[sev] = severity_dist.get(sev, 0) + 1

        if severity_dist:
            lines.append("")
            lines.append("Vulnerability severity distribution:")
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if sev in severity_dist:
                    lines.append(f"  {sev}: {severity_dist[sev]}")

        # Successful vs failed attacks.
        success_count = 0
        failure_count = 0
        for _, data in self.graph.nodes(data=True):
            if data.get("node_type") == "result":
                if data.get("success"):
                    success_count += 1
                else:
                    failure_count += 1

        if success_count or failure_count:
            lines.append("")
            lines.append(f"Attack results: {success_count} successful, {failure_count} failed")

        return "\n".join(lines)
