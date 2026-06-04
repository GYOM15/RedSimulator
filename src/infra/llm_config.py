"""Runtime LLM configuration -- in-memory only, never persisted.

This module manages user-provided LLM settings (provider, model, API key)
that are configured at runtime through the API. The API key is stored as
a SecureString and is NEVER written to disk or logs.

The runtime config OVERRIDES the file-based settings from config.py
for LLM-related fields only.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from src.infra.logging import get_logger
from src.infra.secure import SecureString

logger = get_logger(__name__)


@dataclass
class LLMRuntimeConfig:
    """In-memory LLM configuration. API key never touches disk."""

    provider: str = ""  # "anthropic", "ollama", "openai"
    model: str = ""
    api_key: SecureString | None = field(default=None, repr=False)  # NEVER persisted
    ollama_url: str = ""
    configured: bool = False  # True once user has set config via API

    def to_safe_dict(self) -> dict:
        """Return config WITHOUT the API key -- safe for API responses."""
        return {
            "provider": self.provider,
            "model": self.model,
            "api_key_set": bool(self.api_key),
            "ollama_url": self.ollama_url,
            "configured": self.configured,
        }

    def clear(self) -> None:
        """Securely clear all config including the API key."""
        self.provider = ""
        self.model = ""
        self.api_key = None
        self.ollama_url = ""
        self.configured = False


class LLMConfigManager:
    """Thread-safe manager for runtime LLM configuration."""

    _instance: LLMConfigManager | None = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> LLMConfigManager:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._config = LLMRuntimeConfig()
        return cls._instance

    def configure(
        self,
        provider: str,
        model: str,
        api_key: str = "",
        ollama_url: str = "",
    ) -> dict:
        """Set the LLM configuration. API key is wrapped in SecureString."""
        with self._lock:
            self._config.provider = provider
            self._config.model = model
            self._config.api_key = SecureString(api_key) if api_key else None
            self._config.ollama_url = ollama_url or "http://localhost:11434"
            self._config.configured = True
            logger.info(
                "LLM configured: provider=%s, model=%s, key_set=%s",
                provider,
                model,
                bool(api_key),
            )
            # NOTE: api_key is NOT logged
        return self._config.to_safe_dict()

    def get_config(self) -> LLMRuntimeConfig:
        """Return the current runtime LLM configuration."""
        return self._config

    def get_safe_dict(self) -> dict:
        """Return a dict representation safe for API responses (no API key)."""
        return self._config.to_safe_dict()

    def clear(self) -> None:
        """Clear all runtime LLM configuration from memory."""
        with self._lock:
            self._config.clear()
            logger.info("LLM configuration cleared")

    @property
    def is_configured(self) -> bool:
        """Return True if the runtime LLM config has been set via API."""
        return self._config.configured


# Module-level singleton -- import this from anywhere in the codebase.
llm_config: LLMConfigManager = LLMConfigManager()
