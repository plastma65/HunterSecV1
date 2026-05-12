"""Centralized exception hierarchy for HunterSecV1.

All exceptions inherit from :class:`HuntersecError`. Subclasses are organized
by concern so callers can catch coarse categories (e.g. ``SafetyViolationError``)
without enumerating every leaf type.
"""

from __future__ import annotations


class HuntersecError(Exception):
    """Base for all HunterSecV1 errors."""


# ─── Safety ────────────────────────────────────────────────────────────────


class SafetyViolationError(HuntersecError):
    """Base class for any safety control violation. Never silently swallow."""


class OutOfScopeError(SafetyViolationError):
    """Target is not in the active scope file."""


class BlocklistedCommandError(SafetyViolationError):
    """Command matched the destructive-action blocklist."""


class RateLimitExceededError(SafetyViolationError):
    """Local rate limiter would be exceeded by this call."""


class ScopeNotConfiguredError(SafetyViolationError):
    """No valid scope file is loaded; refusing to proceed."""


# ─── Sandbox ───────────────────────────────────────────────────────────────


class SandboxError(HuntersecError):
    """Base for sandbox / Docker execution failures."""


class SandboxStartupError(SandboxError):
    """Container failed to start."""


class SandboxTimeoutError(SandboxError):
    """Command exceeded its sandbox timeout."""


# ─── LLM ───────────────────────────────────────────────────────────────────


class LLMError(HuntersecError):
    """Base for LLM-related failures."""


class LLMRateLimitError(LLMError):
    """Upstream provider returned rate limit."""


class LLMBudgetExceededError(LLMError):
    """Session token budget would be exceeded."""


class LLMValidationError(LLMError):
    """LLM output failed schema validation."""


# ─── Tools ─────────────────────────────────────────────────────────────────


class ToolError(HuntersecError):
    """Base for tool wrapper failures."""


class ToolNotFoundError(ToolError):
    """Requested tool is not registered."""


class ToolInputError(ToolError):
    """Tool input failed validation."""


# ─── Config ────────────────────────────────────────────────────────────────


class ConfigError(HuntersecError):
    """Configuration file is invalid or missing required keys."""
