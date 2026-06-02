"""Payload intelligence data models.

Defines the annotated payload structure used by the contextual intelligence
system. Each payload carries metadata about its target environment, technique,
and effectiveness so that the smart selector can pick optimal payloads for a
given target.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IntelPayload:
    """A payload with contextual intelligence metadata.

    Attributes:
        text:           The raw payload string to inject.
        attack_type:    Top-level category (sqli, xss, idor, etc.).
        technique:      Sub-technique (auth_bypass, union, error_based, reflected, stored, etc.).
        databases:      Database engines this payload targets.
                        Use ``["any"]`` for database-agnostic payloads.
        contexts:       Injection contexts where this payload is effective.
                        Values: string, numeric, url_param, html_attr, js_string, any.
        waf_bypasses:   WAFs this payload can evade.
                        Values: none, modsecurity, cloudflare, aws_waf, generic.
        severity_boost: 0.0-1.0 score indicating typical effectiveness.
        explanation:    Human-readable explanation of WHY this payload works.
                        Used as context for LLM-based mutation.
        tags:           Additional free-form tags for filtering.
    """

    text: str
    attack_type: str
    technique: str
    databases: list[str]
    contexts: list[str]
    waf_bypasses: list[str]
    severity_boost: float
    explanation: str
    tags: list[str] = field(default_factory=list)


@dataclass
class PayloadStats:
    """Tracks payload effectiveness over time.

    Persisted as part of the feedback loop so that cross-session learning
    can boost payloads that historically succeed against specific technologies.

    Attributes:
        payload_hash:   Stable hash of the payload text.
        total_uses:     Total number of times this payload has been used.
        successes:      Number of successful exploitations.
        by_technology:  Per-technology breakdown of uses and successes.
    """

    payload_hash: str
    total_uses: int = 0
    successes: int = 0
    by_technology: dict[str, dict] = field(default_factory=dict)
    # e.g. {"sqlite": {"uses": 5, "successes": 3}, "mysql": {"uses": 2, "successes": 0}}

    @property
    def success_rate(self) -> float:
        """Overall success rate across all technologies."""
        return self.successes / self.total_uses if self.total_uses > 0 else 0.0

    def tech_success_rate(self, technology: str) -> float:
        """Success rate for a specific technology."""
        tech = self.by_technology.get(technology, {})
        uses = tech.get("uses", 0)
        if uses == 0:
            return 0.0
        return tech.get("successes", 0) / uses
