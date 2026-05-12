"""Unit tests for huntersec.core.state."""

from __future__ import annotations

from pathlib import Path

import pytest

from huntersec.core.state import (
    AgentState,
    Finding,
    FindingModel,
    PlanStep,
    PlanStepModel,
    ToolOutput,
    ValidationResponse,
)


# ── PlanStep TypedDict ─────────────────────────────────────────────────────────


def test_plan_step_creation() -> None:
    step = PlanStep(
        step_id="1",
        tool_name="nmap",
        args={"flags": "-sV"},
        rationale="scan",
        safety_check="in scope",
    )
    assert step["step_id"] == "1"
    assert step["tool_name"] == "nmap"
    assert step["args"]["flags"] == "-sV"


def test_plan_step_model_validates_valid_data() -> None:
    model = PlanStepModel.model_validate(
        {
            "step_id": "1",
            "tool_name": "nmap",
            "args": {"flags": "-sV"},
            "rationale": "Initial scan",
            "safety_check": "Authorized",
        }
    )
    assert model.tool_name == "nmap"
    assert model.args["flags"] == "-sV"


def test_plan_step_model_defaults_empty_args() -> None:
    model = PlanStepModel(step_id="2", tool_name="httpx")
    assert model.args == {}
    assert model.rationale == ""


def test_plan_step_model_rejects_missing_required_fields() -> None:
    with pytest.raises(Exception):
        PlanStepModel.model_validate({})


# ── ToolOutput TypedDict ───────────────────────────────────────────────────────


def test_tool_output_creation() -> None:
    out = ToolOutput(
        step_id="1",
        tool_name="nmap",
        stdout="result",
        stderr="",
        exit_code=0,
        duration_ms=500,
        timestamp="2026-05-12T00:00:00",
    )
    assert out["exit_code"] == 0
    assert out["tool_name"] == "nmap"


def test_tool_output_optional_parsed_field() -> None:
    out: ToolOutput = {
        "step_id": "1",
        "tool_name": "nmap",
        "stdout": "",
        "stderr": "",
        "exit_code": 0,
        "duration_ms": 0,
        "timestamp": "2026-05-12T00:00:00",
        "parsed": {"hosts": []},
    }
    assert out.get("parsed") == {"hosts": []}


# ── Finding TypedDict ──────────────────────────────────────────────────────────


def test_finding_creation() -> None:
    f = Finding(
        category="port",
        severity="info",
        title="Open Port 80",
        detail="HTTP service",
        evidence="80/tcp open",
    )
    assert f["severity"] == "info"
    assert "80" in f["evidence"]


def test_finding_model_validates() -> None:
    fm = FindingModel.model_validate(
        {
            "category": "web",
            "severity": "high",
            "title": "Admin Panel Exposed",
            "detail": "/admin accessible without auth",
            "evidence": "HTTP 200 /admin",
        }
    )
    assert fm.severity == "high"


def test_finding_model_rejects_invalid_severity() -> None:
    with pytest.raises(Exception):
        FindingModel.model_validate(
            {"category": "x", "severity": "ultra", "title": "t", "detail": "", "evidence": ""}
        )


# ── ValidationResponse ─────────────────────────────────────────────────────────


def test_validation_response_sufficient() -> None:
    vr = ValidationResponse.model_validate(
        {
            "decision": "sufficient",
            "reasoning": "Enough data collected.",
            "findings": [],
        }
    )
    assert vr.decision == "sufficient"


def test_validation_response_need_more() -> None:
    vr = ValidationResponse.model_validate(
        {
            "decision": "need_more",
            "reasoning": "Web ports found but no directory enumeration yet.",
            "findings": [
                {
                    "category": "port",
                    "severity": "info",
                    "title": "Open 80",
                    "detail": "HTTP",
                    "evidence": "80/tcp open",
                }
            ],
            "additional_objectives": ["run gobuster on port 80"],
        }
    )
    assert vr.decision == "need_more"
    assert len(vr.findings) == 1
    assert vr.additional_objectives == ["run gobuster on port 80"]


# ── AgentState TypedDict ───────────────────────────────────────────────────────


def test_agent_state_creation() -> None:
    state: AgentState = {
        "session_id": "sess-001",
        "target": "192.0.2.1",
        "scope_file": Path("configs/scope.yaml"),
        "objective": "recon",
        "plan": [],
        "current_step_index": 0,
        "tool_outputs": [],
        "findings": [],
        "report_path": None,
        "token_usage": 0,
        "status": "planning",
        "error": None,
        "loop_count": 0,
        "validation_decision": "",
    }
    assert state["target"] == "192.0.2.1"
    assert state["status"] == "planning"
    assert state["report_path"] is None


def test_agent_state_with_findings() -> None:
    finding = Finding(
        category="port",
        severity="info",
        title="Port 22 open",
        detail="SSH",
        evidence="22/tcp open",
    )
    state: AgentState = {
        "session_id": "s",
        "target": "192.0.2.1",
        "scope_file": Path("scope.yaml"),
        "objective": "recon",
        "plan": [],
        "current_step_index": 0,
        "tool_outputs": [],
        "findings": [finding],
        "report_path": None,
        "token_usage": 100,
        "status": "done",
        "error": None,
        "loop_count": 1,
        "validation_decision": "sufficient",
    }
    assert len(state["findings"]) == 1
    assert state["findings"][0]["severity"] == "info"
