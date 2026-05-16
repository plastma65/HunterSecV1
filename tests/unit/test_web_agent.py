"""Unit tests for huntersec.core.subagents.web_agent.WebAgent."""

from __future__ import annotations

from huntersec.core.subagents.recon_agent import ReconSummary
from huntersec.core.subagents.web_agent import WebAgent
from huntersec.sandbox.executor import ExecutionResult
from huntersec.sandbox.mock import MockSandboxExecutor
from huntersec.tools.registry import default_registry

_TARGET = "192.0.2.1"


def _exec_result(stdout: str) -> ExecutionResult:
    return {"stdout": stdout, "stderr": "", "exit_code": 0, "duration_ms": 5}


def _recon_summary_with_web() -> ReconSummary:
    return ReconSummary(
        target=_TARGET,
        open_ports=[
            {"port": "80", "protocol": "tcp", "service": "http", "version": "nginx"},
        ],
        web_services=[
            {
                "url": "http://192.0.2.1",
                "title": "Welcome",
                "tech_stack": ["nginx"],
                "status_code": 200,
            }
        ],
        hostnames=[],
        os_guess=None,
        errors=[],
    )


def _empty_recon_summary() -> ReconSummary:
    return ReconSummary(
        target=_TARGET,
        open_ports=[],
        web_services=[],
        hostnames=[],
        os_guess=None,
        errors=[],
    )


_GOBUSTER_OUT = (
    "/admin (Status: 200) [Size: 123]\n"
    "/robots.txt (Status: 200) [Size: 45]\n"
    "/.git (Status: 200) [Size: 89]\n"
    "/files (Status: 301) [Size: 200]\n"
)


# ── Tests ─────────────────────────────────────────────────────────────────────


async def test_web_agent_skips_when_no_web_services(safety_filter, audit_logger) -> None:
    mock = MockSandboxExecutor()
    registry = default_registry(mock)
    agent = WebAgent(safety_filter, registry, audit_logger)

    findings = await agent.run(_TARGET, _empty_recon_summary())

    assert findings["directories"] == []
    assert findings["interesting_files"] == []
    # No tool calls when skipped
    assert mock.call_history == []


async def test_web_agent_extracts_directories_from_gobuster(
    safety_filter, audit_logger
) -> None:
    mock = MockSandboxExecutor(scripted_results=[_exec_result(_GOBUSTER_OUT)])
    registry = default_registry(mock)
    agent = WebAgent(safety_filter, registry, audit_logger)

    findings = await agent.run(_TARGET, _recon_summary_with_web())

    assert "/admin" in findings["directories"]
    assert "/robots.txt" in findings["directories"]


async def test_web_agent_identifies_interesting_files(
    safety_filter, audit_logger
) -> None:
    mock = MockSandboxExecutor(scripted_results=[_exec_result(_GOBUSTER_OUT)])
    registry = default_registry(mock)
    agent = WebAgent(safety_filter, registry, audit_logger)

    findings = await agent.run(_TARGET, _recon_summary_with_web())

    assert "/robots.txt" in findings["interesting_files"]
    assert "/.git" in findings["interesting_files"]


async def test_web_agent_flags_wordpress_tech(safety_filter, audit_logger) -> None:
    mock = MockSandboxExecutor(scripted_results=[_exec_result("")])
    registry = default_registry(mock)
    agent = WebAgent(safety_filter, registry, audit_logger)

    recon = _recon_summary_with_web()
    recon["web_services"][0]["tech_stack"] = ["WordPress 5.0", "PHP"]

    findings = await agent.run(_TARGET, recon)
    assert any("WordPress" in v for v in findings["potential_vulns"])


async def test_web_agent_blocked_target_records_error(
    safety_filter, audit_logger
) -> None:
    mock = MockSandboxExecutor()
    registry = default_registry(mock)
    agent = WebAgent(safety_filter, registry, audit_logger)

    recon = _recon_summary_with_web()
    recon["target"] = "8.8.8.8"

    findings = await agent.run("8.8.8.8", recon)
    assert findings["errors"], "expected scope denial"
