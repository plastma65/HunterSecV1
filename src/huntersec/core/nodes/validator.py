"""Validator node — LLM-driven assessment of collected findings."""

from __future__ import annotations

import json
import re
from typing import Any

import structlog
from pydantic import ValidationError

from huntersec.core.prompts import SYSTEM_PROMPT, VALIDATOR_PROMPT
from huntersec.core.state import AgentState, Finding, ValidationResponse
from huntersec.llm.base import ChatMessage
from huntersec.llm.router import LLMRouter
from huntersec.safety.audit import AuditLogger

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

_JSON_BLOCK = re.compile(r"```(?:json)?\s*([\s\S]+?)\s*```")
_MAX_OUTPUT_PREVIEW = 3000  # chars per tool output in validator prompt


def _extract_json(text: str) -> Any:
    m = _JSON_BLOCK.search(text)
    if m:
        return json.loads(m.group(1).strip())
    text = text.strip()
    if text.startswith("{") or text.startswith("["):
        return json.loads(text)
    idx = text.find("{")
    if idx != -1:
        try:
            return json.loads(text[idx:])
        except json.JSONDecodeError:
            pass
    raise json.JSONDecodeError("No valid JSON found in validator response", text, 0)


def _summarise_outputs(tool_outputs: list) -> str:
    parts: list[str] = []
    for out in tool_outputs:
        tool = out.get("tool_name", "unknown")
        stdout = out.get("stdout", "")
        exit_code = out.get("exit_code", "?")
        preview = stdout[:_MAX_OUTPUT_PREVIEW]
        if len(stdout) > _MAX_OUTPUT_PREVIEW:
            preview += f"\n… [truncated, {len(stdout) - _MAX_OUTPUT_PREVIEW} chars omitted]"
        parts.append(f"[{tool} | exit {exit_code}]\n{preview}")
    return "\n\n---\n\n".join(parts) or "No tool outputs collected."


async def validator_node(
    state: AgentState,
    *,
    llm: LLMRouter,
    audit: AuditLogger,
) -> dict:
    """Evaluate collected tool outputs and decide whether to replan or report.

    Args:
        state: Current agent state with all tool outputs collected so far.
        llm: LLM router for validation.
        audit: Audit logger.

    Returns:
        Partial state update with ``findings`` (appended), ``validation_decision``,
        ``status``, and ``token_usage``.
    """
    outputs_summary = _summarise_outputs(list(state.get("tool_outputs", [])))

    prompt = VALIDATOR_PROMPT.format(
        target=state["target"],
        objective=state["objective"],
        tool_outputs_summary=outputs_summary,
    )
    messages: list[ChatMessage] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

    new_findings: list[Finding] = []
    decision = "sufficient"

    try:
        resp = await llm.complete(messages)
        raw = _extract_json(resp.content)
        validated = ValidationResponse.model_validate(raw)
        decision = validated.decision

        for fm in validated.findings:
            new_findings.append(
                Finding(
                    category=fm.category,
                    severity=fm.severity,
                    title=fm.title,
                    detail=fm.detail,
                    evidence=fm.evidence,
                )
            )

        audit.log_event(
            "agent.validation.decision",
            {
                "session_id": state["session_id"],
                "decision": decision,
                "new_findings": len(new_findings),
                "reasoning": validated.reasoning[:200],
            },
        )
        log.info(
            "validator.decision",
            decision=decision,
            new_findings=len(new_findings),
            loop_count=state["loop_count"],
        )
        new_token_usage = state.get("token_usage", 0) + resp.total_tokens

    except (json.JSONDecodeError, ValidationError, Exception) as exc:  # noqa: BLE001
        # On validator failure: default to "sufficient" so we don't loop forever
        log.warning("validator.parse_failed", error=str(exc))
        audit.log_event(
            "agent.validation.error",
            {"session_id": state["session_id"], "error": str(exc)},
        )
        decision = "sufficient"
        new_token_usage = state.get("token_usage", 0)

    return {
        "findings": new_findings,
        "validation_decision": decision,
        "status": "validating",
        "token_usage": new_token_usage,
    }
