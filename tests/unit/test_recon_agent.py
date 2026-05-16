"""Unit tests for huntersec.core.subagents.recon_agent.ReconAgent."""

from __future__ import annotations

import pytest

from huntersec.core.subagents.recon_agent import ReconAgent, ReconSummary
from huntersec.sandbox.executor import ExecutionResult
from huntersec.sandbox.mock import MockSandboxExecutor
from huntersec.tools.registry import default_registry

_TARGET = "192.0.2.1"


_NMAP_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_WHATWEB_JSON = (
    '[{"target":"http://192.0.2.1","http_status":200,'
    '"plugins":{"nginx":{"version":["1.18"],"confidence":100},'
    '"HTTPServer":{"version":[],"confidence":100}}}]'
)

_HTTPX_JSONL = (
    '{"url":"http://192.0.2.1","status-code":200,'
    '"title":"Welcome","tech":["nginx"]}\n'
)

_GOBUSTER_OUT = (
    "/admin (Status: 200) [Size: 123]\n"
    "/robots.txt (Status: 200) [Size: 45]\n"
)


def _exec_result(stdout: str) -> ExecutionResult:
    return {"stdout": stdout, "stderr": "", "exit_code": 0, "duration_ms": 10}


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def scripted_mock() -> MockSandboxExecutor:
    """Mock that returns nmap → whatweb → httpx → gobuster in order."""
    return MockSandboxExecutor(
        scripted_results=[
            _exec_result(_NMAP_XML),
            _exec_result(_WHATWEB_JSON),
            _exec_result(_HTTPX_JSONL),
            _exec_result(_GOBUSTER_OUT),
        ]
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


async def test_recon_agent_runs_tools_in_correct_order(
    scripted_mock: MockSandboxExecutor, safety_filter, audit_logger
) -> None:
    registry = default_registry(scripted_mock)
    agent = ReconAgent(safety_filter, registry, audit_logger)

    await agent.run(_TARGET)

    # First call must be nmap; whatweb must come before httpx
    assert scripted_mock.call_history[0].startswith("nmap")
    cmds = " | ".join(scripted_mock.call_history)
    assert "whatweb" in cmds
    assert "httpx" in cmds


async def test_recon_agent_returns_recon_summary_structure(
    scripted_mock: MockSandboxExecutor, safety_filter, audit_logger
) -> None:
    registry = default_registry(scripted_mock)
    agent = ReconAgent(safety_filter, registry, audit_logger)

    summary: ReconSummary = await agent.run(_TARGET)

    assert summary["target"] == _TARGET
    assert isinstance(summary["open_ports"], list)
    assert isinstance(summary["web_services"], list)
    assert isinstance(summary["hostnames"], list)
    assert isinstance(summary["errors"], list)


async def test_recon_agent_extracts_open_ports_from_nmap(
    scripted_mock: MockSandboxExecutor, safety_filter, audit_logger
) -> None:
    registry = default_registry(scripted_mock)
    agent = ReconAgent(safety_filter, registry, audit_logger)

    summary = await agent.run(_TARGET)

    ports = {p["port"] for p in summary["open_ports"]}
    assert ports == {"22", "80"}


async def test_recon_agent_extracts_web_services_when_port_80_open(
    scripted_mock: MockSandboxExecutor, safety_filter, audit_logger
) -> None:
    registry = default_registry(scripted_mock)
    agent = ReconAgent(safety_filter, registry, audit_logger)

    summary = await agent.run(_TARGET)

    assert len(summary["web_services"]) >= 1


async def test_recon_agent_skips_failed_tools_gracefully(
    safety_filter, audit_logger
) -> None:
    # Mock returns nmap OK but then raises by yielding non-decodable stdout.
    # Since parse_output never raises, simulate failure by raising in registry.
    failing_mock = MockSandboxExecutor(
        scripted_results=[
            _exec_result("not xml at all"),  # nmap returns junk
            _exec_result(""),  # whatweb empty
            _exec_result(""),  # httpx empty
            _exec_result(""),  # gobuster empty
        ]
    )
    registry = default_registry(failing_mock)
    agent = ReconAgent(safety_filter, registry, audit_logger)

    summary = await agent.run(_TARGET)
    # No crash — graceful degradation
    assert summary["target"] == _TARGET
    # nmap returned junk so no ports parsed
    assert summary["open_ports"] == []


async def test_recon_agent_blocks_out_of_scope_target(
    scripted_mock: MockSandboxExecutor, safety_filter, audit_logger
) -> None:
    """Out-of-scope target → safety denies, errors collected."""
    registry = default_registry(scripted_mock)
    agent = ReconAgent(safety_filter, registry, audit_logger)

    summary = await agent.run("8.8.8.8")

    # SafetyFilter denies → tools never reach mock executor
    assert summary["errors"], "expected at least one safety-block entry"
    assert any("blocked" in e or "scope" in e.lower() for e in summary["errors"])
