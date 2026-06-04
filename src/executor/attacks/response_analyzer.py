"""LLM-based response analyzer for subtle attack detection.

When traditional pattern matching can't determine if an attack succeeded,
this module asks Claude to analyze the HTTP response.
"""

from __future__ import annotations

import json

from src.infra.decorators import logged, safe
from src.infra.llm import is_llm_available, llm_chat
from src.infra.logging import get_logger

logger = get_logger(__name__)

_MAX_BODY_LENGTH = 1000
"""Maximum number of characters from the response body sent to the LLM."""

_ANALYSIS_PROMPT = """\
You are a security testing assistant. Analyze the following HTTP response \
to determine whether the attack succeeded.

Attack type: {attack_type}
Payload sent: {payload}
HTTP status code: {status_code}
Response headers: {headers}

Response body (first {max_body_len} chars):
{body}

Did this attack succeed? Respond with ONLY a JSON object (no markdown, no \
extra text) containing:
- "success": true or false
- "confidence": a float between 0.0 and 1.0
- "explanation": a brief one-sentence explanation
"""


@safe(fallback=None)
@logged
def analyze_response(
    attack_type: str,
    payload: str,
    status_code: int,
    response_body: str,
    headers: dict | None = None,
) -> dict | None:
    """Ask Claude to analyze if an attack succeeded.

    This function is wrapped with ``@safe(fallback=None)`` so it never
    crashes the calling handler -- if the LLM is unavailable, mis-configured,
    or returns unparseable output, the caller simply gets ``None`` and can
    fall back to heuristic detection.

    Args:
        attack_type: The kind of attack (e.g. ``"sqli"``, ``"xss"``).
        payload: The exact payload string that was sent.
        status_code: HTTP status code of the target's response.
        response_body: Raw response body text.
        headers: Optional dict of response headers.

    Returns:
        Dict with keys ``success`` (bool), ``confidence`` (float 0-1),
        and ``explanation`` (str).  Returns ``None`` when the LLM is
        unavailable or the response cannot be parsed.
    """
    # Guard: no LLM available means we cannot analyze.
    if not is_llm_available():
        logger.debug("No LLM provider available; skipping LLM analysis")
        return None

    # Truncate the body to keep token usage minimal.
    truncated_body = response_body[:_MAX_BODY_LENGTH]
    headers_str = json.dumps(headers, default=str) if headers else "{}"

    prompt = _ANALYSIS_PROMPT.format(
        attack_type=attack_type,
        payload=payload,
        status_code=status_code,
        headers=headers_str,
        body=truncated_body,
        max_body_len=_MAX_BODY_LENGTH,
    )

    logger.debug("Sending response analysis request to LLM")

    raw_text = llm_chat(
        messages=[{"role": "user", "content": prompt}],
        max_tokens=256,
        json_mode=True,
    ).strip()

    # Parse the JSON. The model should return a bare JSON object, but
    # sometimes wraps it in markdown code fences.
    cleaned = raw_text
    if cleaned.startswith("```"):
        # Strip ```json ... ``` wrappers.
        lines = cleaned.splitlines()
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        cleaned = "\n".join(lines)

    parsed = json.loads(cleaned)

    # Validate expected keys and types.
    result = {
        "success": bool(parsed.get("success", False)),
        "confidence": float(parsed.get("confidence", 0.0)),
        "explanation": str(parsed.get("explanation", "")),
    }

    # Clamp confidence to [0, 1].
    result["confidence"] = max(0.0, min(1.0, result["confidence"]))

    logger.info(
        "LLM analysis for %s attack: success=%s confidence=%.2f",
        attack_type,
        result["success"],
        result["confidence"],
    )

    return result
