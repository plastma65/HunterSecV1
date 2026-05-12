"""Anthropic provider wrapper (claude-* models).

Uses :class:`anthropic.AsyncAnthropic` for non-blocking API calls.
Tool output is sanitized before being forwarded to the API.
"""

from __future__ import annotations

from typing import Any

import structlog

from huntersec.exceptions import LLMError, LLMRateLimitError
from huntersec.llm.base import ChatMessage, CompletionResponse, sanitize_tool_output

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

_DEFAULT_MODEL = "claude-sonnet-4-6"
_MAX_TOKENS_DEFAULT = 4096


class AnthropicProvider:
    """LLM provider backed by Anthropic's Messages API.

    Args:
        api_key: Anthropic API key.  If omitted, the SDK reads
            ``ANTHROPIC_API_KEY`` from the environment.
        default_model: Model to use when callers don't specify one.
        max_tokens: Hard cap on completion tokens per request.

    Example:
        >>> import asyncio
        >>> provider = AnthropicProvider(api_key="sk-ant-...")
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
            import anthropic  # type: ignore[import-untyped]
        except ImportError as exc:
            raise LLMError("anthropic package not installed. Run: pip install anthropic") from exc

        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._default_model = default_model
        self._max_tokens = max_tokens

    def _prepare_messages(self, messages: list[ChatMessage]) -> list[dict[str, Any]]:
        """Sanitize and convert messages to Anthropic API format.

        Args:
            messages: Raw conversation messages.

        Returns:
            List of dicts compatible with the Anthropic Messages API.
        """
        prepared: list[dict[str, Any]] = []
        for msg in messages:
            content = msg.get("content", "")
            if msg.get("is_tool_output"):
                content = sanitize_tool_output(content)
            role = msg.get("role", "user")
            if role == "system":
                # System messages are passed separately in Anthropic API;
                # here we convert them to user messages prefixed with [SYSTEM]
                # to avoid the need for a separate system parameter extraction.
                prepared.append({"role": "user", "content": f"[SYSTEM]\n{content}"})
            else:
                prepared.append({"role": role, "content": content})
        return prepared

    async def complete(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
    ) -> CompletionResponse:
        """Send a completion request to Anthropic.

        Args:
            messages: Ordered conversation messages.
            model: Model override (e.g. ``"claude-opus-4-7"``).

        Returns:
            Normalised :class:`~huntersec.llm.base.CompletionResponse`.

        Raises:
            LLMRateLimitError: On HTTP 429 from Anthropic.
            LLMError: On any other API-level error.
        """
        try:
            import anthropic  # type: ignore[import-untyped]
        except ImportError as exc:
            raise LLMError("anthropic package not installed") from exc

        selected_model = model or self._default_model
        prepared = self._prepare_messages(messages)

        try:
            response = await self._client.messages.create(
                model=selected_model,
                max_tokens=self._max_tokens,
                messages=prepared,  # type: ignore[arg-type]
            )
        except anthropic.RateLimitError as exc:
            log.warning("llm.anthropic.rate_limit", model=selected_model)
            raise LLMRateLimitError(f"Anthropic rate limit: {exc}") from exc
        except anthropic.APIError as exc:
            log.error("llm.anthropic.api_error", model=selected_model, error=str(exc))
            raise LLMError(f"Anthropic API error: {exc}") from exc

        content_text = ""
        if response.content and hasattr(response.content[0], "text"):
            content_text = response.content[0].text

        return CompletionResponse(
            content=content_text,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            model=response.model,
            raw={"id": response.id, "stop_reason": response.stop_reason},
        )
