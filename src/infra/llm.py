"""Unified LLM provider abstraction.

Supports Anthropic (Claude), Ollama (local models), and OpenAI-compatible
APIs through a common interface. The provider is selected via runtime
configuration (set through the API) or falls back to file-based settings.

Usage::

    from src.infra.llm import llm_chat

    response = llm_chat(
        messages=[{"role": "user", "content": "Hello"}],
        system="You are a security analyst.",
        max_tokens=1024,
    )
    # response is a string (the assistant's reply)
"""

from __future__ import annotations

from src.infra.config import settings
from src.infra.decorators import logged, retry
from src.infra.exceptions import LLMError
from src.infra.llm_config import llm_config
from src.infra.logging import get_logger

logger = get_logger(__name__)


def _get_effective_config() -> dict:
    """Get the effective LLM config: runtime overrides file-based settings."""
    runtime = llm_config.get_config()
    if runtime.configured:
        return {
            "provider": runtime.provider,
            "model": runtime.model,
            "api_key": runtime.api_key.get_secret_value() if runtime.api_key else "",
            "ollama_url": runtime.ollama_url,
        }
    # Fall back to file-based settings
    return {
        "provider": settings.llm_provider,
        "model": settings.llm_model,
        "api_key": settings.anthropic_api_key or "",
        "ollama_url": getattr(settings, "ollama_url", "http://localhost:11434"),
    }


@logged
@retry(max_attempts=2, exceptions=(LLMError,))
def llm_chat(
    messages: list[dict[str, str]],
    system: str = "",
    max_tokens: int | None = None,
    temperature: float | None = None,
    json_mode: bool = False,
) -> str:
    """Send a chat request to the configured LLM provider.

    Args:
        messages: List of {"role": "user"|"assistant", "content": "..."}
        system: System prompt (handled differently per provider)
        max_tokens: Max response tokens (default from settings)
        temperature: Sampling temperature (default from settings)
        json_mode: If True, hint that we expect JSON output

    Returns:
        The assistant's response text.

    Raises:
        LLMError: If the LLM call fails or no provider is configured.
    """
    cfg = _get_effective_config()
    provider = cfg["provider"].lower().strip()
    max_tokens = max_tokens or settings.llm_max_tokens
    temperature = temperature if temperature is not None else settings.llm_temperature

    if provider == "anthropic":
        return _call_anthropic(messages, system, max_tokens, temperature, cfg)
    elif provider == "ollama":
        return _call_ollama(messages, system, max_tokens, temperature, json_mode, cfg)
    elif provider == "openai":
        return _call_openai(messages, system, max_tokens, temperature, json_mode, cfg)
    else:
        raise LLMError(f"Unknown LLM provider: {provider}")


def _call_anthropic(
    messages: list[dict[str, str]],
    system: str,
    max_tokens: int,
    temperature: float,
    cfg: dict,
) -> str:
    """Call Anthropic's Claude API."""
    api_key = cfg["api_key"]
    if not api_key:
        raise LLMError("Anthropic API key not configured (set ANTHROPIC_API_KEY)")

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)

        kwargs: dict = {
            "model": cfg["model"],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system

        response = client.messages.create(**kwargs)
        return str(response.content[0].text)

    except ImportError as e:
        raise LLMError("anthropic package not installed") from e
    except LLMError:
        raise
    except Exception as e:
        raise LLMError(f"Anthropic API error: {e}") from e


def _call_ollama(
    messages: list[dict[str, str]],
    system: str,
    max_tokens: int,
    temperature: float,
    json_mode: bool,
    cfg: dict,
) -> str:
    """Call a local Ollama instance via its REST API."""
    import requests

    base_url = cfg["ollama_url"].rstrip("/")
    model = cfg["model"]

    # Build the message list with system prompt
    ollama_messages: list[dict[str, str]] = []
    if system:
        ollama_messages.append({"role": "system", "content": system})
    ollama_messages.extend(messages)

    payload: dict = {
        "model": model,
        "messages": ollama_messages,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
        },
    }
    if json_mode:
        payload["format"] = "json"

    try:
        resp = requests.post(
            f"{base_url}/api/chat",
            json=payload,
            timeout=120,  # Local models can be slow
        )
        resp.raise_for_status()
        data = resp.json()
        return str(data["message"]["content"])
    except requests.ConnectionError as e:
        raise LLMError(f"Cannot connect to Ollama at {base_url}. Is Ollama running?") from e
    except requests.Timeout as e:
        raise LLMError(f"Ollama request timed out (model: {model})") from e
    except LLMError:
        raise
    except Exception as e:
        raise LLMError(f"Ollama error: {e}") from e


def _call_openai(
    messages: list[dict[str, str]],
    system: str,
    max_tokens: int,
    temperature: float,
    json_mode: bool,
    cfg: dict,
) -> str:
    """Call OpenAI-compatible API (works with OpenAI, Together, Groq, etc.)."""
    import requests

    api_key = cfg["api_key"]
    if not api_key:
        raise LLMError("OpenAI API key not configured")

    # Build the message list with system prompt
    openai_messages: list[dict[str, str]] = []
    if system:
        openai_messages.append({"role": "system", "content": system})
    openai_messages.extend(messages)

    payload: dict = {
        "model": cfg["model"],
        "messages": openai_messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        return str(data["choices"][0]["message"]["content"])
    except requests.ConnectionError as e:
        raise LLMError("Cannot connect to OpenAI API") from e
    except requests.Timeout as e:
        raise LLMError(f"OpenAI request timed out (model: {cfg['model']})") from e
    except LLMError:
        raise
    except Exception as e:
        raise LLMError(f"OpenAI API error: {e}") from e


def is_llm_available() -> bool:
    """Check if an LLM provider is configured and reachable."""
    cfg = _get_effective_config()
    provider = cfg["provider"].lower().strip()

    if provider == "anthropic" or provider == "openai":
        return bool(cfg["api_key"])
    elif provider == "ollama":
        try:
            import requests

            resp = requests.get(f"{cfg['ollama_url']}/api/tags", timeout=3)
            return bool(resp.status_code == 200)
        except Exception:
            return False
    return False
