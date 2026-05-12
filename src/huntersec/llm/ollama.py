"""Ollama provider — calls local Ollama server via httpx (no SDK dependency).

Ollama runs models locally (e.g. ``qwen2.5:14b``).  This provider hits the
``/api/chat`` endpoint directly with :class:`httpx.AsyncClient`.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from huntersec.exceptions import LLMError, LLMRateLimitError
from huntersec.llm.base import ChatMessage, CompletionResponse, sanitize_tool_output

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

_DEFAULT_HOST = "http://localhost:11434"
_DEFAULT_MODEL = "qwen2.5:14b"
_CHAT_PATH = "/api/chat"


class OllamaProvider:
    """LLM provider backed by a local Ollama server.

    Args:
        host: Base URL of the Ollama server (default: ``http://localhost:11434``).
        default_model: Model tag to use when callers don't specify one.
        timeout: HTTP request timeout in seconds.

    Example:
        >>> provider = OllamaProvider(host="http://localhost:11434")
        >>> import asyncio
        >>> resp = asyncio.run(provider.complete([
        ...     {"role": "user", "content": "Hello"}
        ... ]))
    """

    def __init__(
        self,
        host: str = _DEFAULT_HOST,
        default_model: str = _DEFAULT_MODEL,
        timeout: float = 120.0,
    ) -> None:
        self._host = host.rstrip("/")
        self._default_model = default_model
        self._timeout = timeout

    def _prepare_messages(self, messages: list[ChatMessage]) -> list[dict[str, Any]]:
        """Sanitize and convert messages to Ollama API format.

        Args:
            messages: Raw conversation messages.

        Returns:
            List of dicts compatible with the Ollama ``/api/chat`` endpoint.
        """
        prepared: list[dict[str, Any]] = []
        for msg in messages:
            content = msg.get("content", "")
            if msg.get("is_tool_output"):
                content = sanitize_tool_output(content)
            prepared.append({"role": msg.get("role", "user"), "content": content})
        return prepared

    async def complete(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
    ) -> CompletionResponse:
        """Send a completion request to the local Ollama server.

        Args:
            messages: Ordered conversation messages.
            model: Model tag override (e.g. ``"llama3.2:3b"``).

        Returns:
            Normalised :class:`~huntersec.llm.base.CompletionResponse`.

        Raises:
            LLMRateLimitError: On HTTP 429 (unlikely for local Ollama but
                possible if a reverse proxy sits in front).
            LLMError: On connection errors or unexpected HTTP status codes.
        """
        selected_model = model or self._default_model
        prepared = self._prepare_messages(messages)
        url = f"{self._host}{_CHAT_PATH}"
        payload: dict[str, Any] = {
            "model": selected_model,
            "messages": prepared,
            "stream": False,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(url, json=payload)
        except httpx.ConnectError as exc:
            raise LLMError(
                f"Cannot connect to Ollama at {self._host}. Is the server running? (ollama serve)"
            ) from exc
        except httpx.TimeoutException as exc:
            raise LLMError(f"Ollama request timed out after {self._timeout}s") from exc

        if response.status_code == 429:  # noqa: PLR2004
            raise LLMRateLimitError("Ollama rate limit (429).")
        if response.status_code != 200:  # noqa: PLR2004
            raise LLMError(f"Ollama returned HTTP {response.status_code}: {response.text[:200]}")

        data: dict[str, Any] = response.json()
        content = data.get("message", {}).get("content", "")
        input_tokens: int = data.get("prompt_eval_count", 0)
        output_tokens: int = data.get("eval_count", 0)

        return CompletionResponse(
            content=content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=selected_model,
            raw={"done": data.get("done"), "total_duration": data.get("total_duration")},
        )
