"""Docker sandbox — hardened container execution for offensive tools.

All tool invocations MUST go through :class:`~huntersec.sandbox.executor.SandboxExecutor`.
See ``docs/architecture.md`` §Sandbox for hardening details.
"""

from __future__ import annotations

from huntersec.sandbox.container import ManagedContainer
from huntersec.sandbox.executor import ExecutionResult, SandboxExecutor
from huntersec.sandbox.mock import MockSandboxExecutor

__all__ = [
    "ExecutionResult",
    "ManagedContainer",
    "MockSandboxExecutor",
    "SandboxExecutor",
]
