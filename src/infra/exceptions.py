"""
Exception hierarchy for RedSimulator.

Provides structured, client-safe error types for every module in the
security-testing pipeline: Scanner, Expert, Generator, Executor, Reporter,
and their external dependencies.

Design goals:
    - Every exception carries a machine-readable ``code`` for programmatic
      handling and a human-readable ``message``.
    - ``to_safe_dict()`` returns a representation that is safe to send to
      API clients (no stack traces, no internal file paths, no secrets).
    - An optional ``details`` dict holds structured context that stays
      within the server boundary (logging, observability) but is *not*
      forwarded to clients by default.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class RedSimulatorError(Exception):
    """Base exception for every error raised inside RedSimulator.

    Attributes:
        code:    Machine-readable error code (e.g. ``"INTERNAL_ERROR"``).
        message: Human-readable description of what went wrong.
        details: Optional structured context for internal logging.
                 Must never contain secrets or absolute file-system paths.
    """

    code: str = "INTERNAL_ERROR"

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict = details or {}

    def to_safe_dict(self) -> dict:
        """Return a client-safe dictionary (no stack traces, no internals)."""
        return {"error": self.code, "message": self.message}

    def __repr__(self) -> str:
        cls = type(self).__name__
        if self.details:
            return f"{cls}(code={self.code!r}, message={self.message!r}, details={self.details!r})"
        return f"{cls}(code={self.code!r}, message={self.message!r})"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class ConfigError(RedSimulatorError):
    """Invalid or missing configuration value."""

    code: str = "CONFIG_ERROR"


# ---------------------------------------------------------------------------
# Pipeline (orchestrator level)
# ---------------------------------------------------------------------------


class PipelineError(RedSimulatorError):
    """Orchestrator-level pipeline failure."""

    code: str = "PIPELINE_ERROR"


class PhaseError(PipelineError):
    """A specific pipeline phase failed.

    Attributes:
        phase_name: Identifier of the phase that failed
                    (e.g. ``"scanning"``, ``"generation"``).
    """

    code: str = "PHASE_ERROR"

    def __init__(
        self,
        message: str,
        phase_name: str,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.phase_name = phase_name

    def to_safe_dict(self) -> dict:
        base = super().to_safe_dict()
        base["phase_name"] = self.phase_name
        return base


class PipelineTimeoutError(PipelineError):
    """Pipeline exceeded its allotted time budget."""

    code: str = "PIPELINE_TIMEOUT"


# ---------------------------------------------------------------------------
# Scanner module
# ---------------------------------------------------------------------------


class ScanError(RedSimulatorError):
    """Scanner module failure."""

    code: str = "SCAN_ERROR"


class ScanTimeoutError(ScanError):
    """A scan exceeded its time limit."""

    code: str = "SCAN_TIMEOUT"


class ToolError(ScanError):
    """A scanner tool (e.g. nmap, nikto) failed.

    Attributes:
        tool_name: Name of the tool that failed.
    """

    code: str = "TOOL_ERROR"

    def __init__(
        self,
        message: str,
        tool_name: str,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.tool_name = tool_name

    def to_safe_dict(self) -> dict:
        base = super().to_safe_dict()
        base["tool_name"] = self.tool_name
        return base


class AgentError(ScanError):
    """ReAct agent reasoning failure inside the Scanner."""

    code: str = "AGENT_ERROR"


# ---------------------------------------------------------------------------
# Expert system
# ---------------------------------------------------------------------------


class ExpertError(RedSimulatorError):
    """Expert system failure."""

    code: str = "EXPERT_ERROR"


class RuleError(ExpertError):
    """A specific expert rule failed.

    Attributes:
        rule_name: Identifier of the rule that failed.
    """

    code: str = "RULE_ERROR"

    def __init__(
        self,
        message: str,
        rule_name: str,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.rule_name = rule_name

    def to_safe_dict(self) -> dict:
        base = super().to_safe_dict()
        base["rule_name"] = self.rule_name
        return base


# ---------------------------------------------------------------------------
# Generator (LLM / offline payload generation)
# ---------------------------------------------------------------------------


class GeneratorError(RedSimulatorError):
    """Payload generation failure (LLM or offline)."""

    code: str = "GENERATOR_ERROR"


# ---------------------------------------------------------------------------
# Executor (attack execution)
# ---------------------------------------------------------------------------


class ExecutorError(RedSimulatorError):
    """Attack execution failure."""

    code: str = "EXECUTOR_ERROR"


class AttackError(ExecutorError):
    """A specific attack vector failed.

    Attributes:
        vector_id: Identifier of the attack vector that failed.
    """

    code: str = "ATTACK_ERROR"

    def __init__(
        self,
        message: str,
        vector_id: str,
        details: dict | None = None,
    ) -> None:
        super().__init__(message, details)
        self.vector_id = vector_id

    def to_safe_dict(self) -> dict:
        base = super().to_safe_dict()
        base["vector_id"] = self.vector_id
        return base


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


class ReporterError(RedSimulatorError):
    """Report generation failure."""

    code: str = "REPORTER_ERROR"


class RAGError(ReporterError):
    """RAG chatbot failure inside the Reporter."""

    code: str = "RAG_ERROR"


# ---------------------------------------------------------------------------
# External services
# ---------------------------------------------------------------------------


class ExternalServiceError(RedSimulatorError):
    """An external dependency (Docker, nmap, Playwright, LLM API) failed."""

    code: str = "EXTERNAL_SERVICE_ERROR"


class LLMError(ExternalServiceError):
    """Claude API or other LLM provider error."""

    code: str = "LLM_ERROR"


class DockerServiceError(ExternalServiceError):
    """Docker daemon or container is not available."""

    code: str = "DOCKER_SERVICE_ERROR"


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------


class ProxyError(RedSimulatorError):
    """MITM proxy module failure."""

    code: str = "PROXY_ERROR"


class ProxyNotAvailableError(ProxyError):
    """mitmproxy is not installed or cannot be started."""

    code: str = "PROXY_NOT_AVAILABLE"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class AuthError(RedSimulatorError):
    """Base exception for authentication failures."""

    code: str = "AUTH_ERROR"


class AuthenticationFailedError(AuthError):
    """Authentication was rejected by the target (bad credentials, etc.)."""

    code: str = "AUTH_FAILED"


class TokenExpiredError(AuthError):
    """An authentication token has expired and could not be refreshed."""

    code: str = "TOKEN_EXPIRED"
