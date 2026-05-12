"""LLM abstraction layer.

Provides a unified :class:`~huntersec.llm.router.LLMRouter` that routes
completion requests across multiple providers with token-budget enforcement
and automatic fallback on rate-limit errors.
"""

from __future__ import annotations

from huntersec.llm.base import ChatMessage, CompletionResponse, LLMProvider, sanitize_tool_output
from huntersec.llm.fake import FakeLLMProvider
from huntersec.llm.router import LLMRouter

__all__ = [
    "ChatMessage",
    "CompletionResponse",
    "FakeLLMProvider",
    "LLMProvider",
    "LLMRouter",
    "sanitize_tool_output",
]
