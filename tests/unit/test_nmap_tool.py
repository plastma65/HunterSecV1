"""Unit tests for huntersec.tools.recon.nmap.NmapTool."""

from __future__ import annotations

from huntersec.sandbox.mock import MockSandboxExecutor
from huntersec.tools.base import ToolInput, ToolResult
from huntersec.tools.recon.nmap import NmapTool

# ── RFC 5737 test target (never a real target) ─────────────────────────────────
_TARGET = "192.0.2.1"

_SAMPLE_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
  <host starttime="1000000000" endtime="1000000010">
    <status state="up" reason="echo-reply"/>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

_EMPTY_XML = '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"></nmaprun>'


# ── build_command ──────────────────────────────────────────────────────────────


def test_nmap_build_command_contains_target() -> None:
    tool = NmapTool()
    cmd = tool.build_command(ToolInput(target=_TARGET))
    assert _TARGET in cmd


def test_nmap_build_command_default_flags() -> None:
    tool = NmapTool()
    cmd = tool.build_command(ToolInput(target=_TARGET))
    assert "-sV" in cmd
    assert "-oX" in cmd
    assert "-" in cmd  # XML to stdout


def test_nmap_build_command_no_raw_syn_flag() -> None:
    """Security requirement: -sS (raw SYN) must never appear in default command."""
    tool = NmapTool()
    cmd = tool.build_command(ToolInput(target=_TARGET))
    assert "-sS" not in cmd


def test_nmap_build_command_custom_flags() -> None:
    tool = NmapTool()
    cmd = tool.build_command(ToolInput(target=_TARGET, args={"flags": "-p 80,443"}))
    assert "-p 80,443" in cmd


def test_nmap_build_command_not_shell_true() -> None:
    """Command must be a plain string tokenizable with shlex — no shell metacharacters."""
    import shlex

    tool = NmapTool()
    cmd = tool.build_command(ToolInput(target=_TARGET))
    tokens = shlex.split(cmd)
    assert tokens[0] == "nmap"


# ── parse_output ───────────────────────────────────────────────────────────────


def test_nmap_parse_output_extracts_two_ports() -> None:
    tool = NmapTool()
    result = ToolResult(stdout=_SAMPLE_XML, stderr="", exit_code=0, duration_ms=100)
    parsed = tool.parse_output(result)
    assert len(parsed["hosts"]) == 1
    host = parsed["hosts"][0]
    assert host["address"] == "192.0.2.1"
    assert host["state"] == "up"
    assert len(host["ports"]) == 2


def test_nmap_parse_output_extracts_service_info() -> None:
    tool = NmapTool()
    result = ToolResult(stdout=_SAMPLE_XML, stderr="", exit_code=0, duration_ms=100)
    parsed = tool.parse_output(result)
    ports = parsed["hosts"][0]["ports"]
    ssh_port = next(p for p in ports if p["port"] == "22")
    assert ssh_port["service"]["name"] == "ssh"
    assert "OpenSSH" in ssh_port["service"]["product"]


def test_nmap_parse_output_empty_xml_returns_empty_hosts() -> None:
    tool = NmapTool()
    result = ToolResult(stdout=_EMPTY_XML, stderr="", exit_code=0, duration_ms=10)
    parsed = tool.parse_output(result)
    assert parsed["hosts"] == []


def test_nmap_parse_output_invalid_xml_returns_error() -> None:
    tool = NmapTool()
    result = ToolResult(stdout="not xml at all <<<", stderr="", exit_code=1, duration_ms=5)
    parsed = tool.parse_output(result)
    assert "error" in parsed


def test_nmap_parse_output_empty_stdout_returns_empty() -> None:
    tool = NmapTool()
    result = ToolResult(stdout="", stderr="", exit_code=0, duration_ms=0)
    parsed = tool.parse_output(result)
    assert parsed["hosts"] == []


# ── run (integration with MockSandboxExecutor) ─────────────────────────────────


async def test_nmap_run_uses_mock_executor() -> None:
    mock = MockSandboxExecutor(
        default_result={
            "stdout": _SAMPLE_XML,
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 200,
        }
    )
    tool = NmapTool()
    result = await tool.run(ToolInput(target=_TARGET), mock)
    assert result.exit_code == 0
    assert result.parsed is not None
    assert len(result.parsed["hosts"]) == 1


async def test_nmap_run_records_command_in_history() -> None:
    mock = MockSandboxExecutor()
    tool = NmapTool()
    await tool.run(ToolInput(target=_TARGET), mock)
    assert len(mock.call_history) == 1
    assert "nmap" in mock.call_history[0]
    assert _TARGET in mock.call_history[0]
