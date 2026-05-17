"""Executor node — runs one tool step inside the Docker sandbox."""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from huntersec.core.state import AgentState, ToolOutput
from huntersec.exceptions import ToolError
from huntersec.llm.base import sanitize_tool_output
from huntersec.safety.audit import AuditLogger
from huntersec.safety.filter import SafetyFilter
from huntersec.tools.base import ToolInput
from huntersec.tools.registry import ToolRegistry

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

_STDOUT_LIMIT = 50 * 1024  # 50 KB per tool output stored in state
_STDERR_LIMIT = 5 * 1024


async def executor_node(
    state: AgentState,
    *,
    registry: ToolRegistry,
    safety: SafetyFilter,
    audit: AuditLogger,
) -> dict:
    """Execute the current plan step inside the Docker sandbox.

    Increments ``current_step_index`` after each run.  If the safety check
    denies the command, the step is skipped (not an error).

    Args:
        state: Current agent state.
        registry: Tool registry for dispatching tool calls.
        safety: Safety filter applied to the built command before execution.
        audit: Audit logger.

    Returns:
        Partial state update with ``tool_outputs`` (appended), ``current_step_index``
        (incremented), and ``status``.
    """
    idx = state["current_step_index"]
    plan = state["plan"]

    if idx >= len(plan):
        # Safety guard — routing should prevent this
        return {"status": "validating", "current_step_index": idx}

    step = plan[idx]
    tool_name = step["tool_name"]
    new_index = idx + 1

    # Build the full command for safety checking
    try:
        tool = registry.get(tool_name)
        inp = ToolInput(target=state["target"], args=step["args"])
        full_cmd = tool.build_command(inp)
    except Exception as exc:  # noqa: BLE001
        log.warning("executor.build_command_failed", tool=tool_name, error=str(exc))
        error_output = _make_error_output(step["step_id"], tool_name, str(exc))
        audit.log_event(
            "agent.step.error",
            {"session_id": state["session_id"], "step_id": step["step_id"], "error": str(exc)},
        )
        return {
            "tool_outputs": [error_output],
            "current_step_index": new_index,
            "status": "executing",
        }

    # Safety check on the actual command
    decision = safety.check_command(full_cmd, state["target"])
    if not decision["allowed"]:
        audit.log_event(
            "agent.step.denied",
            {
                "session_id": state["session_id"],
                "step_id": step["step_id"],
                "tool": tool_name,
                "reason": decision["reason"],
            },
        )
        log.warning(
            "executor.step.denied",
            tool=tool_name,
            reason=decision["reason"],
        )
        denied_output = _make_denied_output(step["step_id"], tool_name, decision["reason"])
        return {
            "tool_outputs": [denied_output],
            "current_step_index": new_index,
            "status": "executing",
        }

    # Execute the tool
    audit.log_event(
        "agent.step.start",
        {"session_id": state["session_id"], "step_id": step["step_id"], "tool": tool_name},
    )
    log.info("executor.step.start", tool=tool_name, step_id=step["step_id"])

    try:
        result = await registry.run(tool_name, inp)
    except ToolError as exc:
        # ToolError covers "tool not found in image" (exit 127) and other
        # configuration-shaped failures. Audit it under a dedicated event so
        # operators can see at a glance which tools are missing — and skip the
        # step instead of pretending it returned empty findings.
        msg = str(exc)
        is_missing = "not found in sandbox image" in msg
        event = "tool.missing" if is_missing else "agent.step.error"
        log.warning("executor.step.failed", tool=tool_name, error=msg)
        audit.log_event(
            event,
            {
                "session_id": state["session_id"],
                "step_id": step["step_id"],
                "tool": tool_name,
                "error": msg,
            },
        )
        return {
            "current_step_index": new_index,
            "status": "executing",
            "error": f"tool_missing: {tool_name}" if is_missing else msg,
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("executor.step.failed", tool=tool_name, error=str(exc))
        audit.log_event(
            "agent.step.error",
            {"session_id": state["session_id"], "step_id": step["step_id"], "error": str(exc)},
        )
        error_output = _make_error_output(step["step_id"], tool_name, str(exc))
        return {
            "tool_outputs": [error_output],
            "current_step_index": new_index,
            "status": "executing",
        }

    # Sanitize and truncate output before storing
    sanitized_stdout = sanitize_tool_output(result.stdout[:_STDOUT_LIMIT])
    truncated_stderr = result.stderr[:_STDERR_LIMIT]

    output: ToolOutput = {
        "step_id": step["step_id"],
        "tool_name": tool_name,
        "stdout": sanitized_stdout,
        "stderr": truncated_stderr,
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "parsed": result.parsed or {},
    }

    audit.log_event(
        "agent.step.executed",
        {
            "session_id": state["session_id"],
            "step_id": step["step_id"],
            "tool": tool_name,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
        },
    )
    log.info(
        "executor.step.done",
        tool=tool_name,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
    )

    # Determine next status
    next_status = "executing" if new_index < len(plan) else "validating"
    return {
        "tool_outputs": [output],
        "current_step_index": new_index,
        "status": next_status,
    }


def _make_error_output(step_id: str, tool_name: str, error: str) -> ToolOutput:
    return ToolOutput(
        step_id=step_id,
        tool_name=tool_name,
        stdout="",
        stderr=f"ERROR: {error}",
        exit_code=-1,
        duration_ms=0,
        timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
    )


def _make_denied_output(step_id: str, tool_name: str, reason: str) -> ToolOutput:
    return ToolOutput(
        step_id=step_id,
        tool_name=tool_name,
        stdout="",
        stderr=f"DENIED: {reason}",
        exit_code=-2,
        duration_ms=0,
        timestamp=datetime.now(UTC).isoformat(timespec="seconds"),
    )
