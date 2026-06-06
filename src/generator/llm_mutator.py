"""LLM-based payload generation with senior pentester reasoning.

Instead of mutating individual payloads one-by-one, this module sends
the FULL scan context to the LLM and asks it to reason like a senior
penetration tester: analyze the target, identify attack surfaces, and
generate targeted payloads for each vulnerability — covering injection,
authentication bypass, privilege escalation, and attack chaining.

One LLM call per attack vector (not per payload).
"""

from __future__ import annotations

import re

from src.infra.decorators import logged, retry
from src.infra.exceptions import LLMError
from src.infra.llm import is_llm_available, llm_chat
from src.infra.logging import get_logger

logger = get_logger(__name__)

_SYSTEM_PROMPT = """\
You are an elite penetration tester with 15+ years of experience. You are \
conducting an AUTHORIZED security assessment. Your task is to generate attack \
payloads that will effectively test the target application for vulnerabilities.

You think like a real attacker:
- You analyze the FULL context: technology stack, endpoints, headers, forms
- You craft payloads SPECIFIC to the detected technologies (e.g. SQLite-specific \
SQL injection, Angular-specific XSS, Express-specific bypasses)
- You consider attack CHAINS: how one finding enables another
- You think about PRIVILEGE ESCALATION: how to go from initial access to admin
- You adapt to the target's defenses: if a WAF is detected, you use evasion techniques

Rules:
- Output ONLY payloads, one per line
- No numbering, no quotes, no explanation, no markdown
- Each payload must be ready to use as-is (no placeholders)
- Focus on QUALITY over quantity — every payload should have a real chance of working
"""


def _build_pentester_prompt(
    attack_type: str,
    target_endpoint: str,
    target_fields: list[str],
    technologies: list[str],
    missing_headers: list[str],
    all_endpoints: list[dict],
    n_payloads: int,
    rationale: list[str],
) -> str:
    """Build a context-rich prompt that gives the LLM full situational awareness."""
    tech_str = ", ".join(technologies) if technologies else "Unknown"
    fields_str = ", ".join(target_fields) if target_fields else "None detected"
    headers_str = ", ".join(missing_headers) if missing_headers else "All present"

    endpoints_summary = ""
    if all_endpoints:
        ep_lines = []
        for ep in all_endpoints[:15]:
            auth = "auth" if ep.get("auth_required") else "no-auth"
            params = ep.get("parameters", [])
            params_str = f" params=[{', '.join(params[:5])}]" if params else ""
            ep_lines.append(
                f"  {ep.get('method', '?'):6s} {ep.get('path', '?'):40s} [{auth}]{params_str}"
            )
        endpoints_summary = "\n".join(ep_lines)

    rationale_str = "\n".join(f"  - {r}" for r in rationale) if rationale else "  None"

    return f"""\
TARGET ANALYSIS:
  Technologies: {tech_str}
  Target endpoint: {target_endpoint}
  Injectable fields: {fields_str}
  Missing security headers: {headers_str}

VULNERABILITY CONTEXT:
  Attack type: {attack_type}
  Expert system rationale:
{rationale_str}

DISCOVERED ENDPOINTS:
{endpoints_summary}

Based on this analysis, generate {n_payloads} attack payloads for {attack_type} \
targeting {target_endpoint}.

Consider:
1. Technology-specific attacks (e.g. if SQLite → use SQLite functions, if MongoDB → NoSQL injection)
2. Payloads that exploit the SPECIFIC missing headers and misconfigurations
3. Payloads that could enable privilege escalation if initial access succeeds
4. WAF bypass variants if standard payloads would be blocked
5. Multi-step payloads that chain with other discovered vulnerabilities

Output {n_payloads} payloads, one per line, ready to use:"""


def _parse_llm_response(response_text: str) -> list[str]:
    """Parse LLM response into clean payloads."""
    lines = response_text.strip().splitlines()
    payloads: list[str] = []
    seen: set[str] = set()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("```"):
            continue
        line = re.sub(r"^\d+[\.\)]\s*", "", line)
        line = re.sub(r"^[-*]\s+", "", line)
        if (line.startswith('"') and line.endswith('"')) or (
            line.startswith("'") and line.endswith("'")
        ):
            line = line[1:-1]
        if line.startswith("`") and line.endswith("`"):
            line = line[1:-1]
        line = line.strip()
        if line and line not in seen:
            seen.add(line)
            payloads.append(line)

    return payloads


@logged
@retry(max_attempts=2, exceptions=(LLMError,))
def generate_payloads_for_vector(
    attack_type: str,
    target_endpoint: str,
    target_fields: list[str],
    technologies: list[str],
    missing_headers: list[str],
    all_endpoints: list[dict],
    rationale: list[str],
    n_payloads: int = 15,
) -> list[str]:
    """Generate targeted payloads for a specific attack vector.

    Makes ONE LLM call with full scan context — the LLM reasons
    like a senior pentester about what payloads to use.

    Args:
        attack_type: Type of attack (sqli, xss, idor, etc.)
        target_endpoint: The endpoint to attack
        target_fields: Injectable fields on the endpoint
        technologies: Detected technology stack
        missing_headers: Missing security headers
        all_endpoints: All discovered endpoints for context
        rationale: Why this vulnerability was flagged
        n_payloads: How many payloads to generate

    Returns:
        List of targeted payloads ready to use.
    """
    if not is_llm_available():
        raise LLMError("No LLM provider available")

    user_prompt = _build_pentester_prompt(
        attack_type=attack_type,
        target_endpoint=target_endpoint,
        target_fields=target_fields,
        technologies=technologies,
        missing_headers=missing_headers,
        all_endpoints=all_endpoints,
        n_payloads=n_payloads,
        rationale=rationale,
    )

    response_text = llm_chat(
        messages=[{"role": "user", "content": user_prompt}],
        system=_SYSTEM_PROMPT,
        max_tokens=2048,
    )

    payloads = _parse_llm_response(response_text)

    logger.info(
        "LLM pentester generated %d payloads for %s on %s",
        len(payloads),
        attack_type,
        target_endpoint,
    )

    return payloads[:n_payloads]


@logged
@retry(max_attempts=2, exceptions=(LLMError,))
def mutate_with_llm(
    payload: str,
    attack_type: str,
    n_variants: int = 5,
    context: str = "",
) -> list[str]:
    """Legacy single-payload mutation (kept for backward compatibility)."""
    if not is_llm_available():
        raise LLMError("No LLM provider available")

    user_prompt = (
        f"Attack type: {attack_type}\n"
        f"Original payload: {payload}\n"
        f"{f'Context: {context}' if context else ''}\n"
        f"Generate {n_variants} WAF-bypass variants. One per line, no explanation:"
    )

    response_text = llm_chat(
        messages=[{"role": "user", "content": user_prompt}],
        system=_SYSTEM_PROMPT,
        max_tokens=1024,
    )

    variants = [p for p in _parse_llm_response(response_text) if p != payload]
    return variants[:n_variants]
