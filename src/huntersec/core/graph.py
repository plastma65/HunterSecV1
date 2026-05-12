"""LangGraph state machine for the HunterSecV1 agent.

Graph topology:

    START → planner → executor ──(more steps)──→ executor
                                └─(steps done)──→ validator ──(need_more & loops<3)──→ planner
                                                            └─(sufficient | max_loops)──→ reporter
                                                                                        └── END
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from langgraph.graph import END, START, StateGraph

from huntersec.core.nodes.executor import executor_node
from huntersec.core.nodes.planner import planner_node
from huntersec.core.nodes.reporter import reporter_node
from huntersec.core.nodes.validator import validator_node
from huntersec.core.state import AgentState

if TYPE_CHECKING:
    from langgraph.graph.state import CompiledStateGraph

    from huntersec.llm.router import LLMRouter
    from huntersec.safety.audit import AuditLogger
    from huntersec.safety.filter import SafetyFilter
    from huntersec.tools.registry import ToolRegistry

_MAX_LOOPS = 3


def _route_after_executor(state: AgentState) -> str:
    """Continue executing or move to validation when all steps are done."""
    if state["status"] == "error":
        return "reporter"
    if state["current_step_index"] < len(state["plan"]):
        return "executor"
    return "validator"


def _route_after_validator(state: AgentState) -> str:
    """Replan if validator says need_more (up to _MAX_LOOPS); otherwise report."""
    if state["status"] == "error":
        return "reporter"
    if state["validation_decision"] == "need_more" and state["loop_count"] < _MAX_LOOPS:
        return "planner"
    return "reporter"


def build_graph(
    llm: LLMRouter,
    registry: ToolRegistry,
    safety: SafetyFilter,
    audit: AuditLogger,
) -> CompiledStateGraph:
    """Build and compile the LangGraph state machine.

    Args:
        llm: LLM router shared across planner and validator.
        registry: Tool registry used by the executor.
        safety: Safety filter applied in the planner and executor.
        audit: Audit logger injected into every node.

    Returns:
        Compiled LangGraph ready for ``ainvoke`` / ``invoke``.
    """
    graph: StateGraph = StateGraph(AgentState)

    # Bind dependencies to each node via closures
    async def _planner(state: AgentState) -> dict:
        return await planner_node(state, llm=llm, safety=safety, audit=audit)

    async def _executor(state: AgentState) -> dict:
        return await executor_node(state, registry=registry, safety=safety, audit=audit)

    async def _validator(state: AgentState) -> dict:
        return await validator_node(state, llm=llm, audit=audit)

    async def _reporter(state: AgentState) -> dict:
        return await reporter_node(state, audit=audit)

    graph.add_node("planner", _planner)
    graph.add_node("executor", _executor)
    graph.add_node("validator", _validator)
    graph.add_node("reporter", _reporter)

    graph.add_edge(START, "planner")
    graph.add_edge("planner", "executor")
    graph.add_conditional_edges("executor", _route_after_executor)
    graph.add_conditional_edges("validator", _route_after_validator)
    graph.add_edge("reporter", END)

    return graph.compile()
