"""ReconAgent must not synthesize web_services when no web port is observed.

Previously, ReconAgent fell back to "probe anyway" when nmap returned zero
open ports, which caused empty machines to show up in reports as if they
exposed HTTP. See ``docs/e2e_test_report.md`` Issue 3.
"""

from __future__ import annotations

import pytest

from huntersec.core.subagents.recon_agent import ReconAgent
from huntersec.sandbox.executor import ExecutionResult
from huntersec.sandbox.mock import MockSandboxExecutor
from huntersec.tools.registry import default_registry

_TARGET = "192.0.2.1"


def _result(stdout: str, exit_code: int = 0) -> ExecutionResult:
    return {"stdout": stdout, "stderr": "", "exit_code": exit_code, "duration_ms": 5}


_NMAP_NO_OPEN_PORTS = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports/>
  </host>
</nmaprun>
"""

_NMAP_PORT_80_ONLY = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_NMAP_PORT_443_ONLY = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_WHATWEB_JSON = (
    '[{"target":"http://192.0.2.1","http_status":200,'
    '"plugins":{"nginx":{"version":["1.18"],"confidence":100}}}]'
)
_HTTPX_JSONL = '{"url":"http://192.0.2.1","status-code":200,"title":"Welcome","tech":["nginx"]}\n'


# ── Tests ────────────────────────────────────────────────────────────────────


async def test_recon_agent_does_not_synthesize_web_services_when_ports_empty(
    safety_filter, audit_logger
) -> None:
    mock = MockSandboxExecutor(
        scripted_results=[
            _result(_NMAP_NO_OPEN_PORTS),
            # Whatweb / httpx / gobuster results queued in case they're called;
            # the contract is they MUST NOT be called.
            _result(_WHATWEB_JSON),
            _result(_HTTPX_JSONL),
            _result(""),
        ]
    )
    registry = default_registry(mock)
    agent = ReconAgent(safety_filter, registry, audit_logger)

    summary = await agent.run(_TARGET)

    assert summary["open_ports"] == []
    assert summary["web_services"] == []
    # Only nmap should have run; web tools skipped because no web port.
    assert len(mock.call_history) == 1
    assert mock.call_history[0].startswith("nmap")


@pytest.mark.parametrize(
    "nmap_xml,expected_port",
    [(_NMAP_PORT_80_ONLY, "80"), (_NMAP_PORT_443_ONLY, "443")],
)
async def test_recon_agent_adds_web_services_when_web_port_detected(
    safety_filter, audit_logger, nmap_xml: str, expected_port: str
) -> None:
    mock = MockSandboxExecutor(
        scripted_results=[
            _result(nmap_xml),
            _result(_WHATWEB_JSON),
            _result(_HTTPX_JSONL),
            _result(""),
        ]
    )
    registry = default_registry(mock)
    agent = ReconAgent(safety_filter, registry, audit_logger)

    summary = await agent.run(_TARGET)

    ports = {p["port"] for p in summary["open_ports"]}
    assert expected_port in ports
    assert len(summary["web_services"]) >= 1
    # Web tools were called this time.
    cmds = " | ".join(mock.call_history)
    assert "whatweb" in cmds
    assert "httpx" in cmds
