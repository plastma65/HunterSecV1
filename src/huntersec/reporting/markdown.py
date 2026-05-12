"""Markdown report generator for HunterSecV1 agent sessions."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from huntersec.core.state import AgentState, Finding, ToolOutput

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_badge(sev: str) -> str:
    badges = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🟢 LOW",
        "info": "🔵 INFO",
    }
    return badges.get(sev.lower(), sev.upper())


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f["severity"].lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _format_nmap_table(tool_outputs: list[ToolOutput]) -> str:
    """Extract open port table from nmap ToolOutput entries."""
    nmap_outputs = [o for o in tool_outputs if o["tool_name"] == "nmap"]
    if not nmap_outputs:
        return "_No nmap output recorded._\n"

    rows: list[str] = ["| Port | Protocol | State | Service | Version |",
                        "|------|----------|-------|---------|---------|"]
    found_any = False
    for out in nmap_outputs:
        parsed: dict[str, Any] = out.get("parsed") or {}
        for host in parsed.get("hosts", []):
            for port in host.get("ports", []):
                svc = port.get("service", {})
                name = svc.get("name", "")
                product = svc.get("product", "")
                version = svc.get("version", "")
                svc_str = f"{product} {version}".strip() if (product or version) else name
                rows.append(
                    f"| {port.get('port', '')} | {port.get('protocol', 'tcp')} "
                    f"| {port.get('state', '')} | {name} | {svc_str} |"
                )
                found_any = True
    if not found_any:
        return "_No open ports detected by nmap._\n"
    return "\n".join(rows) + "\n"


def _format_web_findings(tool_outputs: list[ToolOutput]) -> str:  # noqa: PLR0912
    """Summarise web tool output (gobuster, ffuf, whatweb, httpx)."""
    parts: list[str] = []
    web_tools = ["gobuster", "ffuf", "whatweb", "httpx"]
    for tool_name in web_tools:
        tool_outs = [o for o in tool_outputs if o["tool_name"] == tool_name]
        if not tool_outs:
            continue
        parts.append(f"### {tool_name.capitalize()}")
        for out in tool_outs:
            parsed: dict[str, Any] = out.get("parsed") or {}
            if tool_name in ("gobuster", "ffuf"):
                paths = parsed.get("paths", parsed.get("results", []))
                if paths:
                    for p in paths[:20]:
                        path_str = p.get("path") or p.get("word", "")
                        status = p.get("status", "")
                        parts.append(f"- `{path_str}` (HTTP {status})")
                else:
                    parts.append("_No paths discovered._")
            elif tool_name == "whatweb":
                techs = parsed.get("technologies", {})
                if techs:
                    for tech, info in list(techs.items())[:15]:
                        ver = info.get("version") or ""
                        parts.append(f"- **{tech}** {ver}".rstrip())
                else:
                    parts.append("_No technologies detected._")
            elif tool_name == "httpx":
                for svc in parsed.get("services", [])[:10]:
                    url = svc.get("url", "")
                    code = svc.get("status_code", "")
                    title = svc.get("title", "")
                    techs = ", ".join(svc.get("technologies", []))
                    parts.append(f"- `{url}` [{code}] {title} — {techs}".rstrip(" —"))
        parts.append("")
    return "\n".join(parts) if parts else "_No web tools ran._\n"


class MarkdownReporter:
    """Generate markdown security assessment reports from :class:`~huntersec.core.state.AgentState`.

    Example:
        >>> from pathlib import Path
        >>> reporter = MarkdownReporter()
        >>> state = {
        ...     "session_id": "abc", "target": "192.0.2.1",
        ...     "scope_file": Path("scope.yaml"), "objective": "recon",
        ...     "findings": [], "tool_outputs": [], "token_usage": 0,
        ...     "status": "done",
        ... }
        >>> md = reporter.generate(state)
        >>> "192.0.2.1" in md
        True
    """

    def generate(self, state: AgentState) -> str:
        """Render the full markdown report as a string.

        Args:
            state: Final agent state after the session completes.

        Returns:
            Complete markdown document as a string.
        """
        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        target = state["target"]
        session_id = state["session_id"]
        objective = state.get("objective", "recon")
        scope_file = str(state.get("scope_file", ""))
        findings: list[Finding] = list(state.get("findings", []))
        tool_outputs: list[ToolOutput] = list(state.get("tool_outputs", []))
        token_usage = state.get("token_usage", 0)

        # Sort findings by severity
        findings_sorted = sorted(
            findings, key=lambda f: _SEVERITY_ORDER.get(f["severity"].lower(), 99)
        )
        counts = _count_by_severity(findings)

        lines: list[str] = [
            f"# Recon Report: {target}",
            f"_Generated: {now} | Session: {session_id}_",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"- **Target:** `{target}`",
            f"- **Objective:** {objective}",
            f"- **Scope file:** `{scope_file}`",
            f"- **Tools run:** {len(tool_outputs)}",
            f"- **Token usage:** {token_usage:,}",
            (
                f"- **Findings:** {len(findings)} total "
                f"({counts['critical']} critical / {counts['high']} high / "
                f"{counts['medium']} medium / {counts['low']} low / {counts['info']} info)"
            ),
            "",
            "---",
            "",
            "## Open Ports & Services",
            "",
            _format_nmap_table(tool_outputs),
            "",
            "---",
            "",
            "## Web Findings",
            "",
            _format_web_findings(tool_outputs),
            "",
            "---",
            "",
            "## Detailed Findings",
            "",
        ]

        if not findings_sorted:
            lines.append("_No structured findings extracted._")
        else:
            for finding in findings_sorted:
                badge = _severity_badge(finding["severity"])
                lines += [
                    f"### [{badge}] {finding['title']}",
                    "",
                    f"**Category:** {finding['category']}",
                    "",
                    f"**Detail:** {finding['detail']}",
                    "",
                    "**Evidence:**",
                    "",
                    f"```\n{finding['evidence']}\n```",
                    "",
                ]

        lines += [
            "---",
            "",
            "## Raw Tool Outputs",
            "",
        ]
        for out in tool_outputs:
            tool_name = out["tool_name"]
            ts = out.get("timestamp", "")
            exit_code = out.get("exit_code", "?")
            duration = out.get("duration_ms", 0)
            lines += [
                f"<details><summary>{tool_name} — exit {exit_code} "
                f"({duration} ms) @ {ts}</summary>",
                "",
                "```",
                out.get("stdout", "")[:4096],
                "```",
                "",
                "</details>",
                "",
            ]

        lines += [
            "---",
            "",
            "## Timeline",
            "",
            "| Time | Tool | Exit | Duration |",
            "|------|------|------|----------|",
        ]
        for out in tool_outputs:
            lines.append(
                f"| {out.get('timestamp', '')[:19]} "
                f"| {out['tool_name']} "
                f"| {out.get('exit_code', '?')} "
                f"| {out.get('duration_ms', 0)} ms |"
            )

        lines += [
            "",
            "---",
            "",
            "_Report generated by HunterSecV1. For authorized security testing only._",
        ]

        return "\n".join(lines)

    def save(self, state: AgentState, output_dir: Path) -> Path:
        """Generate and write the report to a file.

        Args:
            state: Final agent state.
            output_dir: Directory to write the ``.md`` file into.
                Created automatically if it does not exist.

        Returns:
            Absolute path of the written report file.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"{state['session_id']}.md"
        report_path.write_text(self.generate(state), encoding="utf-8")
        return report_path
