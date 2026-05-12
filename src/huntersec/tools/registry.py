"""Tool registry — central registry of all available tool wrappers."""

from __future__ import annotations

import structlog

from huntersec.exceptions import ToolNotFoundError
from huntersec.sandbox.executor import SandboxExecutor
from huntersec.tools.base import BaseTool, ToolInput, ToolResult

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class ToolRegistry:
    """Central registry mapping tool names to :class:`~huntersec.tools.base.BaseTool` instances.

    Args:
        executor: :class:`~huntersec.sandbox.executor.SandboxExecutor` passed to
            every tool's :meth:`~huntersec.tools.base.BaseTool.run` call.

    Example:
        >>> from huntersec.sandbox.mock import MockSandboxExecutor
        >>> from huntersec.tools.recon.nmap import NmapTool
        >>> registry = ToolRegistry(MockSandboxExecutor())
        >>> registry.register(NmapTool())
        >>> "nmap" in registry.list_tools()
        True
    """

    def __init__(self, executor: SandboxExecutor) -> None:
        self._executor = executor
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool instance under its name.

        Args:
            tool: Tool to register.  Overwrites any existing tool with the same name.
        """
        self._tools[tool.name] = tool
        log.debug("tool.registered", name=tool.name, category=str(tool.category))

    def get(self, name: str) -> BaseTool:
        """Look up a tool by name.

        Args:
            name: Tool name as defined by :attr:`~huntersec.tools.base.BaseTool.name`.

        Returns:
            The registered :class:`~huntersec.tools.base.BaseTool`.

        Raises:
            ToolNotFoundError: If no tool with that name is registered.
        """
        if name not in self._tools:
            raise ToolNotFoundError(
                f"Tool {name!r} is not registered. "
                f"Available: {sorted(self._tools)}"
            )
        return self._tools[name]

    async def run(self, name: str, inp: ToolInput) -> ToolResult:
        """Execute a named tool and return its result.

        Args:
            name: Tool name.
            inp: Validated tool input.

        Returns:
            :class:`~huntersec.tools.base.ToolResult` from the tool execution.

        Raises:
            ToolNotFoundError: If the tool is not registered.
        """
        tool = self.get(name)
        log.info("tool.run.start", name=name, target=inp.target)
        result = await tool.run(inp, self._executor)
        log.info(
            "tool.run.end",
            name=name,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
        )
        return result

    def list_tools(self) -> list[str]:
        """Return sorted list of registered tool names."""
        return sorted(self._tools)


def default_registry(executor: SandboxExecutor) -> ToolRegistry:
    """Create a :class:`ToolRegistry` pre-populated with the 5 default recon tools.

    Args:
        executor: Sandbox executor passed to each tool.

    Returns:
        Populated :class:`ToolRegistry` with nmap, gobuster, ffuf, whatweb, httpx.
    """
    from huntersec.tools.recon.ffuf import FfufTool
    from huntersec.tools.recon.gobuster import GobusterTool
    from huntersec.tools.recon.httpx_tool import HttpxTool
    from huntersec.tools.recon.nmap import NmapTool
    from huntersec.tools.recon.whatweb import WhatwebTool

    registry = ToolRegistry(executor)
    for tool in [NmapTool(), GobusterTool(), FfufTool(), WhatwebTool(), HttpxTool()]:
        registry.register(tool)
    return registry
