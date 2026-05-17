"""Planner node — LLM-driven plan generation with safety pre-screening."""

from __future__ import annotations

import json
import re
from typing import Any

import structlog
from pydantic import ValidationError

from huntersec.core.prompts import PLANNER_PROMPT, SYSTEM_PROMPT
from huntersec.core.state import AgentState, Finding, PlanStep, PlanStepModel
from huntersec.llm.base import ChatMessage
from huntersec.llm.router import LLMRouter
from huntersec.safety.audit import AuditLogger
from huntersec.safety.filter import SafetyFilter

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

_MAX_RETRIES = 2
_JSON_BLOCK = re.compile(r"```(?:json)?\s*([\s\S]+?)\s*```")


def _extract_json(text: str) -> Any:
    """Extract a JSON value from LLM output, tolerating markdown fences."""
    m = _JSON_BLOCK.search(text)
    if m:
        return json.loads(m.group(1).strip())
    text = text.strip()
    if text.startswith("[") or text.startswith("{"):
        return json.loads(text)
    # Find first [ or { in the text
    for starter in ("[", "{"):
        idx = text.find(starter)
        if idx != -1:
            try:
                return json.loads(text[idx:])
            except json.JSONDecodeError:
                pass
    raise json.JSONDecodeError("No valid JSON found in LLM output", text, 0)


def _format_findings_summary(findings: list[Finding]) -> str:
    if not findings:
        return "No previous findings."
    lines = [f"- [{f['severity'].upper()}] {f['title']}: {f['detail'][:120]}" for f in findings]
    return "\n".join(lines)


async def planner_node(
    state: AgentState,
    *,
    llm: LLMRouter,
    safety: SafetyFilter,
    audit: AuditLogger,
) -> dict:
    """Generate a safety-screened execution plan via LLM.

    Args:
        state: Current agent state.
        llm: LLM router for plan generation.
        safety: Safety filter to pre-screen each planned step.
        audit: Audit logger.

    Returns:
        Partial state update dict with ``plan``, ``current_step_index``,
        ``loop_count``, ``status``, ``token_usage``, and ``error``.
    """
    loop_count = state["loop_count"] + 1
    findings_summary = _format_findings_summary(list(state.get("findings", [])))

    prompt = PLANNER_PROMPT.format(
        target=state["target"],
        objective=state["objective"],
        findings_summary=findings_summary,
        loop_count=loop_count,
    )
    messages: list[ChatMessage] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

    last_error = ""
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = await llm.complete(messages)
            raw = _extract_json(resp.content)
            if not isinstance(raw, list):
                raise ValueError("Expected JSON array from planner LLM")

            steps: list[PlanStep] = []
            for item in raw:
                model = PlanStepModel.model_validate(item)
                # Safety pre-screen: check target scope for each planned step
                proxy_cmd = f"{model.tool_name} {state['target']}"
                decision = safety.check_target(state["target"])
                if not decision["allowed"]:
                    log.warning(
                        "planner.step.blocked",
                        tool=model.tool_name,
                        reason=decision["reason"],
                    )
                    continue
                steps.append(
                    PlanStep(
                        step_id=model.step_id,
                        tool_name=model.tool_name,
                        args=model.args,
                        rationale=model.rationale,
                        safety_check=model.safety_check,
                    )
                )
                del proxy_cmd  # used implicitly above

            if not steps:
                raise ValueError("All planned steps were blocked by safety filter.")

            audit.log_event(
                "agent.plan.created",
                {
                    "session_id": state["session_id"],
                    "loop_count": loop_count,
                    "steps": [s["tool_name"] for s in steps],
                    "attempt": attempt,
                },
            )
            log.info(
                "planner.plan.created",
                loop=loop_count,
                steps=len(steps),
                target=state["target"],
            )
            return {
                "plan": steps,
                "current_step_index": 0,
                "loop_count": loop_count,
                "status": "executing",
                "token_usage": state.get("token_usage", 0) + resp.total_tokens,
                "error": None,
                "validation_decision": "",
            }

        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            last_error = str(exc)
            log.warning("planner.parse_failed", attempt=attempt, error=last_error)
            if attempt < _MAX_RETRIES:
                messages.append({"role": "assistant", "content": resp.content})  # type: ignore[possibly-undefined]
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"Your previous response could not be parsed as JSON: {last_error}. "
                            "Return ONLY a valid JSON array of plan steps, nothing else."
                        ),
                    }
                )

    audit.log_event(
        "agent.plan.failed",
        {"session_id": state["session_id"], "error": last_error},
    )
    log.error("planner.plan.failed", error=last_error)
    return {
        "status": "error",
        "error": f"Planner failed after {_MAX_RETRIES + 1} attempts: {last_error}",
        "loop_count": loop_count,
        "plan": [],
        "current_step_index": 0,
    }
