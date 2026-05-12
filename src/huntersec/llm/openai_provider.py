"""OpenAI provider wrapper (gpt-* and compatible models).

Uses :class:`openai.AsyncOpenAI` for non-blocking API calls.
"""

from __future__ import annotations

from typing import Any

import structlog

from huntersec.exceptions import LLMError, LLMRateLimitError
from huntersec.llm.base import ChatMessage, CompletionResponse, sanitize_tool_output

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

_DEFAULT_MODEL = "gpt-4o-mini"
_MAX_TOKENS_DEFAULT = 4096


class OpenAIProvider:
    """LLM provider backed by the OpenAI Chat Completions API.

    Args:
        api_key: OpenAI API key.  If omitted, the SDK reads ``OPENAI_API_KEY``.
        default_model: Model identifier used when callers don't specify one.
        max_tokens: Hard cap on completion tokens per request.

    Example:
        >>> provider = OpenAIProvider(api_key="sk-...")
        >>> import asyncio
        >>> resp = asyncio.run(provider.complete([
        ...     {"role": "user", "content": "Hello"}
        ... ]))
    """

    def __init__(
        self,
        api_key: str | None = None,
        default_model: str = _DEFAULT_MODEL,
        max_tokens: int = _MAX_TOKENS_DEFAULT,
    ) -> None:
        try:
            import openai  # type: ignore[import-untyped]
        except ImportError as exc:
            raise LLMError("openai package not installed. Run: pip install openai") from exc

        self._client = openai.AsyncOpenAI(api_key=api_key)
        self._default_model = default_model
        self._max_tokens = max_tokens

    def _prepare_messages(self, messages: list[ChatMessage]) -> list[dict[str, Any]]:
        """Sanitize and convert messages to OpenAI Chat format.

        Args:
            messages: Raw conversation messages.

        Returns:
            List of dicts compatible with the OpenAI Chat Completions API.
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
        """Send a completion request to OpenAI.

        Args:
            messages: Ordered conversation messages.
            model: Model override (e.g. ``"gpt-4o"``).

        Returns:
            Normalised :class:`~huntersec.llm.base.CompletionResponse`.

        Raises:
            LLMRateLimitError: On HTTP 429.
            LLMError: On any other API error.
        """
        try:
            import openai  # type: ignore[import-untyped]
        except ImportError as exc:
            raise LLMError("openai package not installed") from exc

        selected_model = model or self._default_model
        prepared = self._prepare_messages(messages)

        try:
            response = await self._client.chat.completions.create(
                model=selected_model,
                messages=prepared,  # type: ignore[arg-type]
                max_tokens=self._max_tokens,
            )
        except openai.RateLimitError as exc:
            log.warning("llm.openai.rate_limit", model=selected_model)
            raise LLMRateLimitError(f"OpenAI rate limit: {exc}") from exc
        except openai.APIError as exc:
            log.exception("llm.openai.api_error", model=selected_model, error=str(exc))
            raise LLMError(f"OpenAI API error: {exc}") from exc

        choice = response.choices[0]
        usage = response.usage

        return CompletionResponse(
            content=choice.message.content or "",
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            model=response.model,
            raw={"id": response.id, "finish_reason": choice.finish_reason},
        )
