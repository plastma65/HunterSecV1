"""Tool base classes for HunterSecV1.

# This module handles offensive primitive: tool execution wrappers.
# Safety: all tools go through SafetyFilter before SandboxExecutor.
# Test targets: RFC 5737 reserved (192.0.2.x, 198.51.100.x, 203.0.113.x)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum, auto
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from huntersec.sandbox.executor import ExecutionResult, SandboxExecutor


class ToolCategory(StrEnum):
    """High-level classification of a tool's purpose."""

    RECON = auto()
    EXPLOIT = auto()
    CRYPTO = auto()
    FORENSICS = auto()
    WEB = auto()
    PWN = auto()
    REVERSE = auto()


class RiskLevel(StrEnum):
    """Risk level of running a tool against a target."""

    PASSIVE = auto()    # no network packets sent to target
    ACTIVE = auto()     # packets sent, detectable by IDS
    INTRUSIVE = auto()  # may crash services or modify target state


class ToolInput(BaseModel):
    """Validated input for a single tool invocation.

    Attributes:
        target: Host, IP, or URL the tool operates against.
        args: Tool-specific keyword arguments (e.g. ``{"flags": "-sV"}``).
        timeout_seconds: Hard timeout enforced by the sandbox executor.
    """

    target: str
    args: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=120, gt=0, le=3600)


class ToolResult(BaseModel):
    """Normalised result returned by :meth:`BaseTool.run`.

    Attributes:
        stdout: Raw standard output captured from the container.
        stderr: Raw standard error captured from the container.
        exit_code: Container process exit code (0 = success).
        duration_ms: Wall-clock execution time in milliseconds.
        parsed: Structured data extracted by :meth:`BaseTool.parse_output`,
            or ``None`` if parsing has not yet run.
    """

    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    parsed: dict[str, Any] | None = None


class BaseTool(ABC):
    """Abstract base class for all HunterSecV1 tool wrappers.

    Subclasses must define three class-level attributes and implement
    :meth:`build_command` and :meth:`parse_output`.  The concrete
    :meth:`run` method orchestrates the full execution pipeline.

    Class Attributes:
        name: Unique tool identifier used by :class:`~huntersec.tools.registry.ToolRegistry`.
        category: High-level category (RECON, WEB, etc.).
        risk_level: How invasive the tool is (PASSIVE → ACTIVE → INTRUSIVE).
        requires_scope: If True (default), tool calls are blocked without a
            valid scope file — never set to False without explicit justification.
    """

    name: ClassVar[str]
    category: ClassVar[ToolCategory]
    risk_level: ClassVar[RiskLevel]
    requires_scope: ClassVar[bool] = True

    @abstractmethod
    def build_command(self, inp: ToolInput) -> str:
        """Return the shell command string for this tool.

        Args:
            inp: Validated tool input.

        Returns:
            Complete command string, tokenised with :func:`shlex.split` by
            the sandbox before execution.  Must NOT use shell metacharacters
            that only work with ``shell=True``.
        """

    @abstractmethod
    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse raw tool output into structured data.

        Args:
            result: Execution result from the sandbox.

        Returns:
            Structured dict.  Must never raise — return ``{"error": "…"}``
            on parse failure so the executor can continue gracefully.
        """

    async def run(self, inp: ToolInput, executor: SandboxExecutor) -> ToolResult:
        """Execute this tool inside the Docker sandbox.

        Args:
            inp: Validated tool input.
            executor: Sandbox executor that runs the command in an isolated
                Docker container.

        Returns:
            :class:`ToolResult` with raw I/O and parsed structured data.
        """
        command = self.build_command(inp)
        raw: ExecutionResult = await executor.run(command, timeout=inp.timeout_seconds)
        result = ToolResult(
            stdout=raw["stdout"],
            stderr=raw["stderr"],
            exit_code=raw["exit_code"],
            duration_ms=raw["duration_ms"],
        )
        result.parsed = self.parse_output(result)
        return result
