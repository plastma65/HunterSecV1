"""Base abstractions for LLM providers.

All provider implementations must satisfy the :class:`LLMProvider` protocol.
:class:`CompletionResponse` is the canonical return type from any provider.
"""

from __future__ import annotations

import re
from typing import Any, NotRequired, Protocol, TypedDict, runtime_checkable

from pydantic import BaseModel, Field

# ── Sanitization patterns ──────────────────────────────────────────────────────
# Strip control characters and patterns attackers may plant in tool output
# to perform prompt injection against the LLM.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_ROLE_DELIMITER = re.compile(r"<\|.*?\|>", re.DOTALL)  # <|im_start|> etc.
_SYSTEM_TAG = re.compile(r"</?system>", re.IGNORECASE)


def sanitize_tool_output(raw: str) -> str:
    """Strip dangerous content from tool output before injecting into an LLM prompt.

    Removes control characters, redacts role-delimiter patterns and ``<system>``
    tags, then wraps the result in ``<tool_output untrusted="true">`` so the
    model treats the content as external and untrusted.

    Args:
        raw: Raw string from a tool (nmap, curl, etc.) execution.

    Returns:
        Sanitized, wrapped string safe for inclusion in an LLM message.
    """
    cleaned = _CONTROL_CHARS.sub("", raw)
    cleaned = _ROLE_DELIMITER.sub("[REDACTED-DELIMITER]", cleaned)
    cleaned = _SYSTEM_TAG.sub("[REDACTED-SYSTEM]", cleaned)
    return f'<tool_output untrusted="true">\n{cleaned}\n</tool_output>'


class ChatMessage(TypedDict, total=False):
    """A single message in a conversation thread.

    Using ``total=False`` allows callers to omit optional fields.
    ``role`` and ``content`` should always be provided.

    Attributes:
        role: Conversation participant: ``"system"``, ``"user"``, ``"assistant"``.
        content: Text of the message.
        is_tool_output: If True, ``content`` came from an external tool and
            MUST be sanitized before being forwarded to the LLM.
    """

    role: str
    content: str
    is_tool_output: NotRequired[bool]


class CompletionResponse(BaseModel):
    """Normalised response from any LLM provider.

    Attributes:
        content: The assistant's reply text.
        input_tokens: Tokens consumed by the prompt.
        output_tokens: Tokens produced in the completion.
        model: Model identifier as reported by the provider.
        raw: Unmodified provider response (for debugging / logging).
    """

    content: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    model: str
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        """Sum of input and output tokens."""
        return self.input_tokens + self.output_tokens


@runtime_checkable
class LLMProvider(Protocol):
    """Structural interface that every LLM provider must implement.

    Callers depend on this protocol rather than concrete implementations,
    so providers can be swapped or mocked without changing call sites.
    """

    async def complete(
        self,
        messages: list[ChatMessage],
        model: str | None = None,
    ) -> CompletionResponse:
        """Send a completion request to the provider.

        Args:
            messages: Ordered list of conversation messages.
            model: Override the provider-default model identifier.

        Returns:
            Normalised :class:`CompletionResponse`.

        Raises:
            LLMRateLimitError: If the upstream provider returns a rate-limit error.
            LLMError: For other upstream errors.
        """
        ...
