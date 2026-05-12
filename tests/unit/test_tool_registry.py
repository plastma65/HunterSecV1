"""Unit tests for huntersec.tools.registry.ToolRegistry."""

from __future__ import annotations

from typing import Any

import pytest

from huntersec.exceptions import ToolNotFoundError
from huntersec.sandbox.mock import MockSandboxExecutor
from huntersec.tools.base import BaseTool, RiskLevel, ToolCategory, ToolInput, ToolResult
from huntersec.tools.registry import ToolRegistry, default_registry


class _EchoTool(BaseTool):
    """Minimal tool for testing — echoes the target back."""

    name = "echo"
    category = ToolCategory.RECON
    risk_level = RiskLevel.PASSIVE

    def build_command(self, inp: ToolInput) -> str:
        return f"echo {inp.target}"

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        return {"output": result.stdout.strip()}


class _OtherTool(BaseTool):
    name = "other"
    category = ToolCategory.WEB
    risk_level = RiskLevel.ACTIVE

    def build_command(self, inp: ToolInput) -> str:
        return f"other {inp.target}"

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        return {}


# ── register / get ─────────────────────────────────────────────────────────────


def test_tool_registry_register_and_get() -> None:
    registry = ToolRegistry(MockSandboxExecutor())
    registry.register(_EchoTool())
    tool = registry.get("echo")
    assert isinstance(tool, _EchoTool)


def test_tool_registry_get_raises_for_unknown_tool() -> None:
    registry = ToolRegistry(MockSandboxExecutor())
    with pytest.raises(ToolNotFoundError, match="not registered"):
        registry.get("nonexistent")


def test_tool_registry_overwrite_existing_tool() -> None:
    registry = ToolRegistry(MockSandboxExecutor())
    registry.register(_EchoTool())
    registry.register(_EchoTool())  # second register — should not raise
    assert registry.list_tools() == ["echo"]


# ── list_tools ─────────────────────────────────────────────────────────────────


def test_tool_registry_list_tools_empty() -> None:
    registry = ToolRegistry(MockSandboxExecutor())
    assert registry.list_tools() == []


def test_tool_registry_list_tools_sorted() -> None:
    registry = ToolRegistry(MockSandboxExecutor())
    registry.register(_OtherTool())
    registry.register(_EchoTool())
    assert registry.list_tools() == ["echo", "other"]


# ── run ────────────────────────────────────────────────────────────────────────


async def test_tool_registry_run_calls_tool_and_returns_result() -> None:
    mock = MockSandboxExecutor(
        default_result={
            "stdout": "192.0.2.1\n",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 10,
        }
    )
    registry = ToolRegistry(mock)
    registry.register(_EchoTool())

    inp = ToolInput(target="192.0.2.1")
    result = await registry.run("echo", inp)
    assert result.exit_code == 0
    assert result.parsed == {"output": "192.0.2.1"}
    assert mock.call_history == ["echo 192.0.2.1"]


async def test_tool_registry_run_raises_for_missing_tool() -> None:
    registry = ToolRegistry(MockSandboxExecutor())
    with pytest.raises(ToolNotFoundError):
        await registry.run("ghost", ToolInput(target="192.0.2.1"))


async def test_tool_registry_run_records_call_history() -> None:
    mock = MockSandboxExecutor()
    registry = ToolRegistry(mock)
    registry.register(_EchoTool())
    await registry.run("echo", ToolInput(target="192.0.2.50"))
    await registry.run("echo", ToolInput(target="192.0.2.51"))
    assert len(mock.call_history) == 2


# ── default_registry ───────────────────────────────────────────────────────────


def test_default_registry_contains_five_tools() -> None:
    registry = default_registry(MockSandboxExecutor())
    tools = registry.list_tools()
    assert set(tools) == {"nmap", "gobuster", "ffuf", "whatweb", "httpx"}


def test_default_registry_nmap_not_none() -> None:
    registry = default_registry(MockSandboxExecutor())
    assert registry.get("nmap") is not None


def test_default_registry_each_tool_has_name() -> None:
    registry = default_registry(MockSandboxExecutor())
    for name in registry.list_tools():
        tool = registry.get(name)
        assert tool.name == name
