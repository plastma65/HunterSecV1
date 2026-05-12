"""Reporter node — generates and saves the markdown assessment report."""

from __future__ import annotations

from pathlib import Path

import structlog

from huntersec.core.state import AgentState
from huntersec.reporting.markdown import MarkdownReporter
from huntersec.safety.audit import AuditLogger

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

_REPORT_DIR = Path("data/reports")


async def reporter_node(state: AgentState, *, audit: AuditLogger) -> dict:
    """Render and save a markdown report from the final agent state.

    Args:
        state: Final agent state containing all findings and tool outputs.
        audit: Audit logger.

    Returns:
        Partial state update with ``report_path``, ``status``.
    """
    reporter = MarkdownReporter()
    try:
        report_path = reporter.save(state, _REPORT_DIR)
        audit.log_event(
            "agent.report.generated",
            {
                "session_id": state["session_id"],
                "report_path": str(report_path),
                "findings_count": len(state.get("findings", [])),
                "tool_outputs_count": len(state.get("tool_outputs", [])),
            },
        )
        log.info(
            "reporter.saved",
            path=str(report_path),
            findings=len(state.get("findings", [])),
        )
        return {"report_path": report_path, "status": "done"}
    except Exception as exc:
        log.exception("reporter.failed", error=str(exc))
        audit.log_event(
            "agent.report.error",
            {"session_id": state["session_id"], "error": str(exc)},
        )
        return {"status": "error", "error": f"Report generation failed: {exc}"}
