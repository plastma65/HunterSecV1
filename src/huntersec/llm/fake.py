"""Fake LLM provider for deterministic unit and integration tests.

:class:`FakeLLMProvider` returns scripted :class:`CompletionResponse` objects
from a pre-configured list, making tests fully reproducible without real API
calls or network access.
"""

from __future__ import annotations

from huntersec.exceptions import LLMError
from huntersec.llm.base import ChatMessage, CompletionResponse


class FakeLLMProvider:
    """Scripted LLM provider for testing.

    Responses are served in order; once the list is exhausted,
    :class:`~huntersec.exceptions.LLMError` is raised unless a
    ``default_response`` is provided.

    Args:
        responses: Ordered list of responses to return on successive calls.
        default_response: Fallback response when the scripted list runs out.
            If ``None`` (default), an :class:`LLMError` is raised instead.
        model: Model name reported in every response.

    Example:
        >>> from huntersec.llm.fake import FakeLLMProvider
        >>> from huntersec.llm.base import CompletionResponse
        >>> fake = FakeLLMProvider([
        ...     CompletionResponse(content="ok", input_tokens=5, output_tokens=2, model="fake"),
        ... ])
        >>> import asyncio
        >>> resp = asyncio.run(fake.complete([{"role": "user", "content": "ping"}]))
        >>> resp.content
        'ok'
    """

    def __init__(
        self,
        responses: list[CompletionResponse] | None = None,
        default_response: CompletionResponse | None = None,
        model: str = "fake-model",
    ) -> None:
        self._responses: list[CompletionResponse] = list(responses or [])
        self._default = default_response
        self._model = model
        self.call_count = 0
        self.received_messages: list[list[ChatMessage]] = []

    async def complete(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
    ) -> CompletionResponse:
        """Return the next scripted response.

        Args:
            messages: Conversation messages (recorded for assertion in tests).
            model: Ignored; the scripted response's model field is used.

        Returns:
            Next :class:`CompletionResponse` from the scripted list.

        Raises:
            LLMError: If the scripted list is exhausted and no default is set.
        """
        self.call_count += 1
        self.received_messages.append(messages)

        if self._responses:
            return self._responses.pop(0)
        if self._default is not None:
            return self._default
        raise LLMError(
            f"FakeLLMProvider: scripted responses exhausted after {self.call_count} call(s). "
            "Add more responses or set a default_response."
        )
