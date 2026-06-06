"""Centralized configuration for RedSimulator.

This module provides a single ``Settings`` instance that externalizes every
tunable parameter -- LLM model names, timeouts, thresholds, service URLs,
and more -- so that they can be overridden via environment variables or a
``.env`` file without touching source code.

Usage::

    from src.infra.config import settings

    # Access any setting as an attribute
    model = settings.llm_model
    key   = settings.anthropic_api_key

For FastAPI dependency injection::

    from src.infra.config import get_settings

    @app.get("/health")
    def health(cfg: Settings = Depends(get_settings)):
        ...

Environment variables
---------------------
All settings accept an environment variable prefixed with ``RS_``
(e.g. ``RS_LLM_MODEL``, ``RS_SCAN_TIMEOUT``).

Two exceptions use their *standard* names without the prefix so that
existing tooling and CI secrets continue to work:

* ``ANTHROPIC_API_KEY`` -- Anthropic SDK key
* ``TARGET_URL``        -- scan target URL
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import ClassVar

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve .env path relative to the project root (2 levels up from this file)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"

# Load .env BEFORE Settings is instantiated so that env vars like
# ANTHROPIC_API_KEY and TARGET_URL are available via os.environ.
load_dotenv(_ENV_FILE, override=True)


class Settings(BaseSettings):
    """Application-wide configuration loaded from env vars / ``.env`` file.

    Every field can be set via an environment variable.  The general rule is
    ``RS_<FIELD_NAME>`` (case-insensitive), but ``ANTHROPIC_API_KEY`` and
    ``TARGET_URL`` intentionally omit the prefix for compatibility with
    standard conventions.
    """

    model_config: ClassVar[SettingsConfigDict] = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        env_prefix="RS_",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------
    # LLM settings
    # ------------------------------------------------------------------
    anthropic_api_key: str | None = Field(
        default=None,
        description="Anthropic API key (reads ANTHROPIC_API_KEY, no RS_ prefix).",
        validation_alias="ANTHROPIC_API_KEY",
    )
    llm_model: str = Field(
        default="claude-sonnet-4-20250514",
        description="LLM model identifier passed to ChatAnthropic / Anthropic client.",
    )
    llm_temperature: float = Field(
        default=0.0,
        description="Sampling temperature for LLM calls.",
    )
    llm_max_tokens: int = Field(
        default=4096,
        description="Maximum number of tokens the LLM may generate per call.",
    )
    llm_provider: str = Field(
        default="anthropic",
        description="LLM provider: 'anthropic' (Claude) or 'ollama' (local).",
    )
    ollama_url: str = Field(
        default="http://localhost:11434",
        description="Ollama server URL for local LLM inference.",
    )
    ollama_model: str = Field(
        default="llama3.1",
        description="Ollama model name (e.g. llama3.1, mistral, codellama).",
    )

    # ------------------------------------------------------------------
    # Scanner settings
    # ------------------------------------------------------------------
    target_url: str = Field(
        default="http://localhost:3000",
        description="Base URL of the target application (reads TARGET_URL, no RS_ prefix).",
        validation_alias="TARGET_URL",
    )
    scan_timeout: int = Field(
        default=300,
        description="Overall scan timeout in seconds.",
    )
    request_timeout: int = Field(
        default=10,
        description="Per-request timeout in seconds for HTTP calls during scanning.",
    )
    max_agent_iterations: int = Field(
        default=2,
        description="Maximum number of ReAct loop iterations for the scanner agent.",
    )
    max_concurrent_requests: int = Field(
        default=10,
        description="Maximum number of concurrent HTTP requests during scanning.",
    )

    # ------------------------------------------------------------------
    # Expert system settings
    # ------------------------------------------------------------------
    rules_path: str = Field(
        default="rules/owasp_rules.json",
        description="Path to the OWASP/expert rules JSON file.",
    )

    # ------------------------------------------------------------------
    # Generator settings
    # ------------------------------------------------------------------
    generator_n_variants: int = Field(
        default=5,
        description="Default number of payload variants to generate per base payload.",
    )
    payload_db_path: str = Field(
        default="data/payloads",
        description="Path to payload database directory.",
    )
    max_payloads_per_vector: int = Field(
        default=20,
        description="Max payloads loaded per attack vector.",
    )

    # ------------------------------------------------------------------
    # Executor settings
    # ------------------------------------------------------------------
    attack_delay: float = Field(
        default=0.2,
        description="Delay in seconds between consecutive attack requests.",
    )
    executor_timeout: int = Field(
        default=30,
        description="Per-request timeout in seconds for the attack executor.",
    )
    rate_limit_adaptive: bool = Field(
        default=True,
        description="Enable adaptive rate limiting (adjusts delay based on server responses).",
    )
    rate_limit_min_delay: float = Field(
        default=0.05,
        description="Minimum delay between requests (seconds) for adaptive rate limiting.",
    )
    rate_limit_max_delay: float = Field(
        default=5.0,
        description="Maximum delay between requests (seconds) for adaptive rate limiting.",
    )
    early_stop_threshold: int = Field(
        default=3,
        description="Stop testing a vector after N consecutive identical responses (0 to disable).",
    )

    # ------------------------------------------------------------------
    # Validation settings
    # ------------------------------------------------------------------
    validation_enabled: bool = Field(
        default=True,
        description="Enable false-positive validation after execution.",
    )
    validation_min_confidence: float = Field(
        default=0.4,
        description="Minimum confidence to keep a finding (below this it is marked as FP).",
    )
    validation_strategies: list[str] = Field(
        default=["differential", "multi_payload"],
        description="Validation strategies to use (differential, multi_payload, llm, timing).",
    )

    # ------------------------------------------------------------------
    # Authentication settings
    # ------------------------------------------------------------------
    auth_type: str = Field(
        default="none",
        description="Auth type: none, basic, cookie, bearer, oauth2.",
    )
    auth_username: str = Field(
        default="",
        description="Auth username (for basic and cookie auth).",
    )
    auth_password: str = Field(
        default="",
        description="Auth password (for basic and cookie auth).",
    )
    auth_token: str = Field(
        default="",
        description="Bearer token (for bearer auth).",
    )
    auth_login_url: str = Field(
        default="",
        description="Login URL for cookie-based auth.",
    )
    auth_token_url: str = Field(
        default="",
        description="Token URL for OAuth2.",
    )
    auth_client_id: str = Field(
        default="",
        description="OAuth2 client ID.",
    )
    auth_client_secret: str = Field(
        default="",
        description="OAuth2 client secret.",
    )

    # ------------------------------------------------------------------
    # Proxy settings
    # ------------------------------------------------------------------
    proxy_host: str = Field(
        default="127.0.0.1",
        description="Proxy listen address.",
    )
    proxy_port: int = Field(
        default=8888,
        description="Proxy listen port.",
    )
    proxy_ssl_insecure: bool = Field(
        default=False,
        description="Skip upstream SSL verification.",
    )
    proxy_max_flows: int = Field(
        default=10000,
        description="Max flows to store.",
    )
    proxy_db_path: str = Field(
        default="data/proxy/flows.db",
        description="SQLite DB path for proxy flows.",
    )

    # ------------------------------------------------------------------
    # API settings
    # ------------------------------------------------------------------
    api_host: str = Field(
        default="0.0.0.0",
        description="Host address the FastAPI server binds to.",
    )
    api_port: int = Field(
        default=8080,
        description="Port the FastAPI server listens on.",
    )
    cors_origins: list[str] = Field(
        default=["http://localhost:5173"],
        description="Allowed CORS origins for the API.",
    )

    # ------------------------------------------------------------------
    # Docker / external service URLs
    # ------------------------------------------------------------------
    chromadb_url: str = Field(
        default="http://localhost:8000",
        description="URL of the ChromaDB vector store service.",
    )
    recon_service_url: str = Field(
        default="http://localhost:8081",
        description="URL of the reconnaissance micro-service (Nmap wrapper).",
    )

    # ------------------------------------------------------------------
    # Campaign settings
    # ------------------------------------------------------------------
    campaign_max_parallel: int = Field(
        default=3,
        description="Max parallel targets in a campaign.",
    )

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )
    log_format: str = Field(
        default="text",
        description="Log output format: 'text' for human-readable, 'json' for structured.",
    )


# Module-level singleton -- import this from anywhere in the codebase.
settings: Settings = Settings()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the application settings singleton.

    Suitable for use as a FastAPI dependency::

        from fastapi import Depends
        from src.infra.config import Settings, get_settings

        @app.get("/info")
        def info(cfg: Settings = Depends(get_settings)):
            return {"model": cfg.llm_model}

    The result is cached so repeated calls (e.g. per-request injection)
    do not re-read the environment.
    """
    return settings
