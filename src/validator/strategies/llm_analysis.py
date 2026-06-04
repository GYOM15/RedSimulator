"""LLM-based validation strategy.

Sends both the attack response and a benign baseline response to Claude
and asks whether the attack genuinely succeeded.  Falls back to a neutral
score when no API key is configured.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import requests

from src.infra.config import settings
from src.infra.llm import is_llm_available, llm_chat
from src.infra.logging import get_logger

from .base import ValidationStrategy

if TYPE_CHECKING:
    from src.models import SingleAttackResult

logger = get_logger(__name__)

_MAX_BODY_LENGTH = 800
"""Maximum number of characters from each response body sent to the LLM."""

_BENIGN_VALUE = "test123"
"""Innocuous value used for the baseline request."""

_VALIDATION_PROMPT = """\
You are a security testing validation assistant. Your job is to determine \
whether an attack truly succeeded by comparing the attack response with a \
benign baseline response.

Attack type: {attack_type}
Payload sent: {payload}

--- ATTACK RESPONSE ---
HTTP status: {attack_status}
Body (first {max_body_len} chars):
{attack_body}

--- BENIGN BASELINE RESPONSE ---
HTTP status: {benign_status}
Body (first {max_body_len} chars):
{benign_body}

Did the attack genuinely succeed, or is this a false positive? \
Respond with ONLY a JSON object (no markdown, no extra text) containing:
- "genuine": true or false
- "confidence": a float between 0.0 and 1.0
- "explanation": a brief one-sentence explanation
"""


class LLMAnalysisStrategy(ValidationStrategy):
    """Use Claude to compare attack and baseline responses.

    Sends both responses to the LLM and asks for a verdict.
    Returns a neutral score (0.5) when the Anthropic API key is
    not configured, effectively removing this strategy from the
    aggregation when LLM access is unavailable.
    """

    name: str = "llm"

    def validate(
        self,
        vector_id: str,
        payload: str,
        target_endpoint: str,
        base_url: str,
        original_result: SingleAttackResult,
        session: requests.Session | None = None,
    ) -> tuple[float, str]:
        # Guard: no LLM available -> skip
        if not is_llm_available():
            logger.debug(
                "No LLM provider available; skipping LLM validation for %s",
                vector_id,
            )
            return -1, "LLM validation skipped (no LLM provider available)."

        # Obtain a benign baseline response
        url = f"{base_url.rstrip('/')}{target_endpoint}"
        http_session = session or requests.Session()

        try:
            benign_resp = http_session.get(
                url,
                params={"q": _BENIGN_VALUE},
                timeout=settings.executor_timeout,
                verify=False,
            )
            benign_status = benign_resp.status_code
            benign_body = benign_resp.text[:_MAX_BODY_LENGTH]
        except requests.RequestException as exc:
            logger.warning(
                "LLM validation: baseline request failed for %s: %s",
                vector_id,
                exc,
            )
            return -1, f"Baseline request failed: {exc}"

        # Infer attack type
        attack_type = self._infer_attack_type(original_result)

        prompt = _VALIDATION_PROMPT.format(
            attack_type=attack_type,
            payload=payload,
            attack_status=original_result.http_status,
            attack_body=original_result.response_snippet[:_MAX_BODY_LENGTH],
            benign_status=benign_status,
            benign_body=benign_body,
            max_body_len=_MAX_BODY_LENGTH,
        )

        try:
            raw_text = llm_chat(
                messages=[{"role": "user", "content": prompt}],
                max_tokens=256,
                json_mode=True,
            ).strip()

            # Strip markdown fences if present
            cleaned = raw_text
            if cleaned.startswith("```"):
                lines = cleaned.splitlines()
                lines = [ln for ln in lines if not ln.strip().startswith("```")]
                cleaned = "\n".join(lines)

            parsed = json.loads(cleaned)
            genuine = bool(parsed.get("genuine", False))
            confidence = float(parsed.get("confidence", 0.5))
            explanation = str(parsed.get("explanation", ""))

            confidence = max(0.0, min(1.0, confidence))

            # If the LLM says it's not genuine, invert the confidence
            score = confidence if genuine else (1.0 - confidence)

            logger.info(
                "LLM validation for %s: genuine=%s, confidence=%.2f",
                vector_id,
                genuine,
                confidence,
            )
            return (
                score,
                f"LLM verdict: {'genuine' if genuine else 'false positive'} — {explanation}",
            )

        except Exception as exc:
            logger.warning(
                "LLM validation failed for %s: %s",
                vector_id,
                exc,
            )
            return -1, f"LLM analysis failed: {exc}"

    @staticmethod
    def _infer_attack_type(result: SingleAttackResult) -> str:
        """Best-effort inference of the attack type for the LLM prompt."""
        vid = result.vector_id.upper()
        detection = result.detection_method.lower()

        mapping = {
            "SQL Injection": ["sqli", "sql"],
            "XSS": ["xss", "cross-site", "script"],
            "IDOR": ["idor"],
            "Path Traversal": ["path_traversal", "traversal"],
            "Command Injection": ["command_injection", "rce", "command"],
            "Auth Bypass": ["auth_bypass", "authentication"],
            "Info Disclosure": ["info_disclosure", "information"],
            "CSRF": ["csrf"],
            "Open Redirect": ["open_redirect", "redirect"],
        }

        for label, keywords in mapping.items():
            for kw in keywords:
                if kw in vid or kw in detection:
                    return label
        return "Unknown"
