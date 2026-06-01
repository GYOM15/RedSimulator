"""LLM-based vulnerability analyst -- second pass after rule engine.

Reviews scan results and the rule-generated attack plan to find
vulnerabilities that deterministic rules may have missed.
"""

from __future__ import annotations

import json
import re

import anthropic

from src.infra.config import settings
from src.infra.decorators import logged, retry, safe
from src.infra.exceptions import LLMError
from src.infra.logging import get_logger
from src.models.attack_plan import AttackPlan, AttackType, AttackVector, Severity
from src.models.scan_result import ScanResult

logger = get_logger(__name__)

# Valid values for enum validation
_VALID_ATTACK_TYPES = {e.value for e in AttackType}
_VALID_SEVERITIES = {e.value for e in Severity}


def _build_prompt(scan: ScanResult, rule_plan: AttackPlan) -> str:
    """Build a structured prompt summarizing scan results and existing plan."""
    # Summarize existing vectors so the LLM knows what's already covered
    if rule_plan.vectors:
        existing_lines = []
        for v in rule_plan.vectors:
            existing_lines.append(
                f"  - [{v.severity.value}] {v.attack_type.value} on {v.target_endpoint}"
            )
        existing_summary = "\n".join(existing_lines)
    else:
        existing_summary = "  (none -- no vectors identified yet)"

    # Format endpoints
    endpoints_lines = []
    for ep in scan.endpoints:
        auth = "auth required" if ep.auth_required else "no auth"
        params = ", ".join(ep.parameters) if ep.parameters else "none"
        endpoints_lines.append(
            f"  - {ep.method} {ep.path} (status={ep.status_code}, {auth}, params=[{params}])"
        )
    endpoints_text = "\n".join(endpoints_lines) if endpoints_lines else "  (none discovered)"

    # Format technologies
    techs_text = ", ".join(scan.technologies) if scan.technologies else "(none detected)"

    # Format missing headers
    headers_text = (
        ", ".join(scan.headers.missing_security_headers)
        if scan.headers.missing_security_headers
        else "(all present)"
    )
    if scan.headers.server_info_leaked:
        headers_text += "\n  Server information leaked: yes"

    # Format forms
    forms_lines = []
    for form in scan.forms:
        fields = ", ".join(f.name for f in form.fields) if form.fields else "none"
        forms_lines.append(
            f"  - {form.method} {form.endpoint or form.action} fields=[{fields}] source={form.source}"
        )
    forms_text = "\n".join(forms_lines) if forms_lines else "  (none found)"

    # Format open ports
    ports_lines = []
    for p in scan.open_ports:
        version = f" ({p.version})" if p.version else ""
        ports_lines.append(f"  - {p.port}/{p.service}{version}")
    ports_text = "\n".join(ports_lines) if ports_lines else "  (none detected)"

    return f"""You are a security analyst reviewing scan results from a web application.
The deterministic rule engine has already identified the following attack vectors:
{existing_summary}

Here are the raw scan results:
- Target: {scan.target}
- Endpoints:
{endpoints_text}
- Technologies: {techs_text}
- Missing security headers: {headers_text}
- Forms:
{forms_text}
- Open ports:
{ports_text}

Find additional vulnerabilities that the rules may have missed. Consider:
- Unusual endpoint patterns
- Technology-specific vulnerabilities
- Combinations of findings that suggest deeper issues
- OWASP Top 10 categories not yet covered

For each vulnerability found, respond with a JSON array:
[{{
  "attack_type": "sqli|xss|idor|path_traversal|auth_bypass|info_disclosure",
  "target_endpoint": "/path",
  "target_fields": ["field1"],
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "owasp_ref": "A0X:2021-Name",
  "rationale": ["reason1", "reason2"],
  "base_payloads": ["payload1"]
}}]

Only report findings NOT already in the existing plan. If everything is covered, return an empty array [].
Respond with ONLY the JSON array, no additional text."""


def _extract_json_array(text: str) -> list[dict]:
    """Extract a JSON array from the LLM response, handling markdown fences."""
    # Strip markdown code fences if present
    cleaned = re.sub(r"```(?:json)?\s*", "", text)
    cleaned = re.sub(r"```\s*$", "", cleaned.strip())
    cleaned = cleaned.strip()

    # Try to find a JSON array in the text
    # First, try direct parse
    try:
        result = json.loads(cleaned)
        if isinstance(result, list):
            return result
        return []
    except json.JSONDecodeError:
        pass

    # Try to find an array pattern in the text
    match = re.search(r"\[.*\]", cleaned, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group(0))
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    return []


@safe(fallback=[])
def _parse_vectors(
    raw_items: list[dict], existing_keys: set[tuple[str, str]], next_id: int
) -> list[AttackVector]:
    """Parse and validate raw dicts into AttackVector objects.

    Filters out duplicates and items with invalid fields. Uses @safe so
    that malformed LLM output never crashes the pipeline.
    """
    vectors: list[AttackVector] = []
    current_id = next_id

    for item in raw_items:
        try:
            # Validate attack_type
            attack_type = item.get("attack_type", "")
            if attack_type not in _VALID_ATTACK_TYPES:
                logger.debug("Skipping LLM vector with invalid attack_type: %s", attack_type)
                continue

            # Validate severity
            severity = item.get("severity", "")
            if severity not in _VALID_SEVERITIES:
                logger.debug("Skipping LLM vector with invalid severity: %s", severity)
                continue

            target_endpoint = item.get("target_endpoint", "")
            if not target_endpoint:
                logger.debug("Skipping LLM vector with empty target_endpoint")
                continue

            # Check for duplicates against existing plan
            key = (attack_type, target_endpoint)
            if key in existing_keys:
                logger.debug(
                    "Skipping duplicate LLM vector: %s on %s", attack_type, target_endpoint
                )
                continue

            # Build the vector with a new sequential ID
            vector = AttackVector(
                id=f"VEC-{current_id:03d}",
                attack_type=AttackType(attack_type),
                target_endpoint=target_endpoint,
                target_fields=item.get("target_fields", []),
                severity=Severity(severity),
                owasp_ref=item.get("owasp_ref", ""),
                rationale=item.get("rationale", []),
                base_payloads=item.get("base_payloads", []),
            )
            vectors.append(vector)
            existing_keys.add(key)
            current_id += 1

        except Exception:
            logger.warning("Failed to parse LLM vector item: %s", item, exc_info=True)
            continue

    return vectors


@logged
@retry(max_attempts=2, exceptions=(LLMError,))
def llm_analyze(scan: ScanResult, rule_plan: AttackPlan) -> list[AttackVector]:
    """Ask Claude to review the scan and find missed vulnerabilities.

    Args:
        scan: Raw scan results.
        rule_plan: Attack plan already produced by rules.

    Returns:
        List of additional AttackVectors found by the LLM.
    """
    # 1. Check for API key availability
    if not settings.anthropic_api_key:
        logger.info("LLM analysis skipped: no ANTHROPIC_API_KEY configured")
        return []

    # 2. Build the prompt
    prompt = _build_prompt(scan, rule_plan)

    # 3. Call Claude via the Anthropic SDK
    try:
        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        response = client.messages.create(
            model=settings.llm_model,
            max_tokens=settings.llm_max_tokens,
            temperature=settings.llm_temperature,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as exc:
        raise LLMError(f"Anthropic API call failed: {exc}") from exc

    # 4. Extract text content from the response
    response_text = ""
    for block in response.content:
        if hasattr(block, "text"):
            response_text += block.text

    if not response_text.strip():
        logger.info("LLM returned empty response")
        return []

    logger.debug("LLM raw response: %s", response_text[:500])

    # 5. Parse JSON from the response
    raw_items = _extract_json_array(response_text)
    if not raw_items:
        logger.info("LLM found no additional vulnerabilities")
        return []

    # 6. Build deduplication keys from existing vectors
    existing_keys: set[tuple[str, str]] = {
        (v.attack_type.value, v.target_endpoint) for v in rule_plan.vectors
    }

    # 7. Determine next vector ID (continue from the last rule-generated ID)
    if rule_plan.vectors:
        last_id_str = rule_plan.vectors[-1].id.replace("VEC-", "")
        try:
            next_id = int(last_id_str) + 1
        except ValueError:
            next_id = len(rule_plan.vectors) + 1
    else:
        next_id = 1

    # 8. Parse and validate vectors
    vectors = _parse_vectors(raw_items, existing_keys, next_id)

    logger.info("LLM analyst identified %d new vectors", len(vectors))
    return vectors
