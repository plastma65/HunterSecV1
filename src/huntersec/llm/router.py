"""LLM Router — provider selection, token budget tracking, and fallback logic.

:class:`LLMRouter` is the single call-site for all LLM completions.  It:

1. Enforces a per-session token budget (raises
   :class:`~huntersec.exceptions.LLMBudgetExceededError` when exhausted).
2. Routes to the configured primary provider.
3. Falls back to the next provider in the list if the primary returns a rate
   limit error (:class:`~huntersec.exceptions.LLMRateLimitError`).
4. Validates that all LLM outputs are treated as untrusted data — callers
   MUST NOT ``eval()`` or ``exec()`` the returned ``content``.
"""

from __future__ import annotations

import structlog

from huntersec.exceptions import LLMBudgetExceededError, LLMError, LLMRateLimitError
from huntersec.llm.base import ChatMessage, CompletionResponse, LLMProvider

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class LLMRouter:
    """Route completion requests across multiple providers with budget tracking.

    Args:
        providers: Ordered list of :class:`~huntersec.llm.base.LLMProvider`
            implementations.  The first provider is tried first; subsequent
            providers are used as fallback on rate-limit errors.
        token_budget: Maximum total tokens (input + output) allowed for this
            session.  Raises :class:`~huntersec.exceptions.LLMBudgetExceededError`
            when the budget is exhausted.
        default_model: Model identifier forwarded to providers when not
            overridden per-call.

    Example:
        >>> from huntersec.llm.fake import FakeLLMProvider
        >>> from huntersec.llm.base import CompletionResponse
        >>> fake = FakeLLMProvider([
        ...     CompletionResponse(content="pong", input_tokens=1,
        ...                        output_tokens=1, model="fake"),
        ... ])
        >>> router = LLMRouter([fake], token_budget=1000)
        >>> import asyncio
        >>> resp = asyncio.run(router.complete([{"role": "user", "content": "ping"}]))
        >>> resp.content
        'pong'
    """

    def __init__(
        self,
        providers: list[LLMProvider],
        token_budget: int = 50_000,
        default_model: str | None = None,
    ) -> None:
        if not providers:
            raise ValueError("LLMRouter requires at least one provider.")
        self._providers = providers
        self._token_budget = token_budget
        self._tokens_used: int = 0
        self._default_model = default_model

    @property
    def tokens_used(self) -> int:
        """Total tokens consumed in this session so far."""
        return self._tokens_used

    @property
    def budget_remaining(self) -> int:
        """Tokens remaining before the session budget is exhausted."""
        return max(0, self._token_budget - self._tokens_used)

    def _check_budget(self) -> None:
        if self._tokens_used >= self._token_budget:
            raise LLMBudgetExceededError(
                f"Session token budget exhausted: used {self._tokens_used} "
                f"of {self._token_budget} tokens."
            )

    async def complete(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
    ) -> CompletionResponse:
        """Complete a conversation, trying providers in order on rate-limit errors.

        Args:
            messages: Ordered conversation messages (may include tool outputs
                marked with ``is_tool_output=True`` — providers will sanitize them).
            model: Model override forwarded to the selected provider.

        Returns:
            :class:`~huntersec.llm.base.CompletionResponse` from the first
            successful provider.

        Raises:
            LLMBudgetExceededError: If the session budget is already exhausted.
            LLMError: If all providers fail for reasons other than rate limiting.
        """
        self._check_budget()

        effective_model = model or self._default_model
        last_exc: LLMError | None = None

        for idx, provider in enumerate(self._providers):
            try:
                response = await provider.complete(messages, model=effective_model)
            except LLMRateLimitError as exc:
                log.warning(
                    "llm.router.rate_limit",
                    provider_index=idx,
                    fallback_available=(idx < len(self._providers) - 1),
                )
                last_exc = exc
                continue  # try next provider
            except LLMError as exc:
                log.error("llm.router.provider_error", provider_index=idx, error=str(exc))
                raise

            self._tokens_used += response.total_tokens
            log.debug(
                "llm.router.complete",
                provider_index=idx,
                model=response.model,
                tokens_used=self._tokens_used,
                budget_remaining=self.budget_remaining,
            )
            return response

        # All providers exhausted due to rate limiting
        raise LLMRateLimitError(
            f"All {len(self._providers)} provider(s) returned rate-limit errors."
        ) from last_exc
