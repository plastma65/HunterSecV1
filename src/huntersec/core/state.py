"""Agent state definitions for the LangGraph orchestrator.

:class:`AgentState` is the single mutable datum threaded through every node
in the state machine.  Fields annotated with ``operator.add`` use append
semantics (LangGraph merges them by concatenation); all other fields use
replace semantics.
"""

from __future__ import annotations

import operator
from pathlib import Path
from typing import Annotated, Literal, NotRequired, TypedDict

from pydantic import BaseModel, Field


class PlanStep(TypedDict):
    """One planned action in the agent's execution plan."""

    step_id: str
    tool_name: str
    args: dict[str, str]
    rationale: str
    safety_check: str


class ToolOutput(TypedDict):
    """Captured output from a single tool execution."""

    step_id: str
    tool_name: str
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    timestamp: str
    parsed: NotRequired[dict]


class Finding(TypedDict):
    """A structured security finding extracted from tool output."""

    category: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    title: str
    detail: str
    evidence: str


class AgentState(TypedDict):
    """Mutable state threaded through the LangGraph execution.

    Fields typed as ``Annotated[list[X], operator.add]`` are accumulative:
    each node returns a list of new items which LangGraph appends to the
    existing list.  All other fields use replace semantics.
    """

    session_id: str
    target: str
    scope_file: Path
    objective: str
    plan: list[PlanStep]
    current_step_index: int
    tool_outputs: Annotated[list[ToolOutput], operator.add]
    findings: Annotated[list[Finding], operator.add]
    report_path: Path | None
    token_usage: int
    status: Literal["planning", "executing", "validating", "reporting", "done", "error"]
    error: str | None
    loop_count: int
    validation_decision: Literal["", "sufficient", "need_more"]


# ── Pydantic validation models (for LLM output parsing) ───────────────────────


class PlanStepModel(BaseModel):
    """Pydantic counterpart of :class:`PlanStep` for LLM output validation."""

    step_id: str
    tool_name: str
    args: dict[str, str] = Field(default_factory=dict)
    rationale: str = ""
    safety_check: str = ""


class FindingModel(BaseModel):
    """Pydantic counterpart of :class:`Finding` for LLM output validation."""

    category: str = "info"
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    title: str
    detail: str = ""
    evidence: str = ""


class ValidationResponse(BaseModel):
    """Structured response from the validator LLM call."""

    decision: Literal["sufficient", "need_more"]
    reasoning: str = ""
    findings: list[FindingModel] = Field(default_factory=list)
    additional_objectives: list[str] = Field(default_factory=list)
