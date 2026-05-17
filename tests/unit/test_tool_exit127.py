"""Unit tests for the exit-127 (command-not-found) handling path.

A sandbox command that exits 127 means the binary is not present in the
Docker image — almost always a configuration mismatch between the tool
registry and ``docker/Dockerfile.kali``. We treat this as a hard
:class:`ToolError`, not as "the tool ran cleanly and found nothing".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from huntersec.core.nodes.executor import executor_node
from huntersec.core.state import AgentState, PlanStep
from huntersec.exceptions import ToolError
from huntersec.sandbox.mock import MockSandboxExecutor
from huntersec.tools.base import ToolInput
from huntersec.tools.recon.nmap import NmapTool
from huntersec.tools.registry import default_registry

# ── BaseTool layer ────────────────────────────────────────────────────────────


async def test_base_tool_raises_tool_error_when_exit_code_is_127() -> None:
    """Exit 127 must surface as ToolError so executors stop pretending."""
    mock = MockSandboxExecutor(
        scripted_results=[
            {"stdout": "", "stderr": "/bin/sh: nmap: not found", "exit_code": 127, "duration_ms": 5}
        ]
    )
    tool = NmapTool()

    with pytest.raises(ToolError, match="not found in sandbox image"):
        await tool.run(ToolInput(target="192.0.2.1"), mock)


async def test_base_tool_does_not_raise_for_normal_exit_codes() -> None:
    """Non-127 exit codes (including failures) flow through normally."""
    mock = MockSandboxExecutor(
        scripted_results=[{"stdout": "<nmaprun/>", "stderr": "", "exit_code": 1, "duration_ms": 5}]
    )
    tool = NmapTool()

    result = await tool.run(ToolInput(target="192.0.2.1"), mock)

    assert result.exit_code == 1
    assert result.parsed is not None


# ── Executor node layer ───────────────────────────────────────────────────────


def _state_with_step(tool_name: str) -> AgentState:
    plan: list[PlanStep] = [
        {
            "step_id": "step-1",
            "tool_name": tool_name,
            "args": {},
            "rationale": "test",
            "safety_check": "in-scope",
        }
    ]
    return {
        "session_id": "test-session",
        "target": "192.0.2.1",
        "scope_file": Path("configs/scope.yaml"),
        "objective": "recon",
        "plan": plan,
        "current_step_index": 0,
        "tool_outputs": [],
        "findings": [],
        "report_path": None,
        "token_usage": 0,
        "status": "executing",
        "error": None,
        "loop_count": 0,
        "validation_decision": "",
    }


async def test_executor_node_logs_tool_missing_event_on_exit_127(
    safety_filter, audit_logger
) -> None:
    """executor_node must log a ``tool.missing`` audit event when a tool 127s."""
    mock = MockSandboxExecutor(
        scripted_results=[{"stdout": "", "stderr": "not found", "exit_code": 127, "duration_ms": 1}]
    )
    registry = default_registry(mock)

    state = _state_with_step("nmap")
    update = await executor_node(state, registry=registry, safety=safety_filter, audit=audit_logger)

    # Step advanced, status still executing so the graph can move on.
    assert update["current_step_index"] == 1
    assert update["status"] == "executing"

    # tool.missing event must be on disk and reference the missing tool.
    audit_text = audit_logger.path.read_text(encoding="utf-8")
    assert '"event":"tool.missing"' in audit_text
    assert '"tool":"nmap"' in audit_text


async def test_executor_node_does_not_append_tool_output_on_exit_127(
    safety_filter, audit_logger
) -> None:
    """A missing tool must NOT show up in ``tool_outputs`` as an empty success."""
    mock = MockSandboxExecutor(
        scripted_results=[{"stdout": "", "stderr": "not found", "exit_code": 127, "duration_ms": 1}]
    )
    registry = default_registry(mock)

    state = _state_with_step("nmap")
    update = await executor_node(state, registry=registry, safety=safety_filter, audit=audit_logger)

    # Either the key is absent or the list is empty — both mean "no fake
    # output was appended for the step we know failed at the image level".
    assert "tool_outputs" not in update or update["tool_outputs"] == []
    assert update.get("error", "").startswith("tool_missing:")
