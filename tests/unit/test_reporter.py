"""Unit tests for huntersec.reporting.markdown.MarkdownReporter."""

from __future__ import annotations

from pathlib import Path

from huntersec.core.state import AgentState, Finding, ToolOutput
from huntersec.reporting.markdown import MarkdownReporter

_TARGET = "192.0.2.1"
_SESSION_ID = "test-session-abc"


def _make_state(
    findings: list[Finding] | None = None,
    tool_outputs: list[ToolOutput] | None = None,
    status: str = "done",
) -> AgentState:
    return AgentState(
        session_id=_SESSION_ID,
        target=_TARGET,
        scope_file=Path("configs/scope.yaml"),
        objective="recon",
        plan=[],
        current_step_index=0,
        tool_outputs=tool_outputs or [],
        findings=findings or [],
        report_path=None,
        token_usage=1500,
        status=status,  # type: ignore[arg-type]
        error=None,
        loop_count=1,
        validation_decision="sufficient",
    )


# ── generate ───────────────────────────────────────────────────────────────────


def test_reporter_generate_contains_target() -> None:
    reporter = MarkdownReporter()
    md = reporter.generate(_make_state())
    assert _TARGET in md


def test_reporter_generate_contains_session_id() -> None:
    reporter = MarkdownReporter()
    md = reporter.generate(_make_state())
    assert _SESSION_ID in md


def test_reporter_generate_contains_executive_summary() -> None:
    reporter = MarkdownReporter()
    md = reporter.generate(_make_state())
    assert "Executive Summary" in md


def test_reporter_generate_lists_finding_title() -> None:
    findings = [
        Finding(
            category="port",
            severity="high",
            title="Open SSH Port 22",
            detail="SSH service running",
            evidence="22/tcp open ssh",
        )
    ]
    reporter = MarkdownReporter()
    md = reporter.generate(_make_state(findings=findings))
    assert "Open SSH Port 22" in md


def test_reporter_generate_shows_finding_count() -> None:
    findings = [
        Finding(category="port", severity="info", title=f"Port {i}", detail="", evidence="")
        for i in range(3)
    ]
    reporter = MarkdownReporter()
    md = reporter.generate(_make_state(findings=findings))
    assert "3" in md  # count appears somewhere in the summary


def test_reporter_generate_includes_raw_tool_output_section() -> None:
    outputs = [
        ToolOutput(
            step_id="1",
            tool_name="nmap",
            stdout="nmap scan results",
            stderr="",
            exit_code=0,
            duration_ms=500,
            timestamp="2026-05-12T00:00:00",
        )
    ]
    reporter = MarkdownReporter()
    md = reporter.generate(_make_state(tool_outputs=outputs))
    assert "Raw Tool Outputs" in md
    assert "nmap" in md


def test_reporter_generate_includes_timeline() -> None:
    outputs = [
        ToolOutput(
            step_id="1",
            tool_name="httpx",
            stdout="",
            stderr="",
            exit_code=0,
            duration_ms=200,
            timestamp="2026-05-12T10:00:00",
        )
    ]
    reporter = MarkdownReporter()
    md = reporter.generate(_make_state(tool_outputs=outputs))
    assert "Timeline" in md
    assert "httpx" in md


def test_reporter_generate_nmap_port_table() -> None:

    nmap_xml = """\
<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94">
<host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80">
<state state="open"/><service name="http" product="Apache" version="2.4.41"/>
</port></ports></host></nmaprun>"""

    from huntersec.tools.base import ToolResult
    from huntersec.tools.recon.nmap import NmapTool

    tool = NmapTool()
    parsed = tool.parse_output(ToolResult(stdout=nmap_xml, stderr="", exit_code=0, duration_ms=0))

    outputs = [
        ToolOutput(
            step_id="1",
            tool_name="nmap",
            stdout=nmap_xml,
            stderr="",
            exit_code=0,
            duration_ms=100,
            timestamp="2026-05-12T00:00:00",
            parsed=parsed,
        )
    ]
    reporter = MarkdownReporter()
    md = reporter.generate(_make_state(tool_outputs=outputs))
    assert "80" in md
    assert "http" in md


def test_reporter_generate_no_findings_message() -> None:
    reporter = MarkdownReporter()
    md = reporter.generate(_make_state(findings=[]))
    assert "No structured findings" in md


def test_reporter_generate_token_usage_shown() -> None:
    reporter = MarkdownReporter()
    md = reporter.generate(_make_state())
    assert "1,500" in md or "1500" in md


# ── save ───────────────────────────────────────────────────────────────────────


def test_reporter_save_creates_file(tmp_path: Path) -> None:
    reporter = MarkdownReporter()
    state = _make_state()
    report_path = reporter.save(state, tmp_path / "reports")
    assert report_path.exists()
    assert report_path.suffix == ".md"


def test_reporter_save_filename_contains_session_id(tmp_path: Path) -> None:
    reporter = MarkdownReporter()
    state = _make_state()
    report_path = reporter.save(state, tmp_path)
    assert _SESSION_ID in report_path.name


def test_reporter_save_creates_output_dir(tmp_path: Path) -> None:
    reporter = MarkdownReporter()
    deep_dir = tmp_path / "a" / "b" / "c"
    assert not deep_dir.exists()
    reporter.save(_make_state(), deep_dir)
    assert deep_dir.exists()


def test_reporter_save_content_matches_generate(tmp_path: Path) -> None:
    reporter = MarkdownReporter()
    state = _make_state()
    path = reporter.save(state, tmp_path)
    assert path.read_text(encoding="utf-8") == reporter.generate(state)
