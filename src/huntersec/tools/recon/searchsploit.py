"""searchsploit — exploit-DB query wrapper (passive, read-only).

# This module handles offensive primitive: exploit-DB metadata lookup.
# Safety: command goes through SafetyFilter + SandboxExecutor.
# Note: this tool **only searches** — it never downloads or executes exploits.
"""

from __future__ import annotations

import json
import shlex
from typing import Any

from huntersec.tools.base import BaseTool, RiskLevel, ToolCategory, ToolInput, ToolResult


class SearchsploitTool(BaseTool):
    """Query the local Exploit-DB index by keyword."""

    name = "searchsploit"
    category = ToolCategory.RECON
    risk_level = RiskLevel.PASSIVE
    requires_scope = False  # purely local DB query — no network I/O

    def build_command(self, inp: ToolInput) -> str:
        """Build a searchsploit query.

        Args:
            inp: ``inp.target`` is used as the search query string.

        Returns:
            ``searchsploit --json <query>`` with proper shell quoting.
        """
        # shlex.quote prevents whitespace / metachar issues without enabling shell=True
        query = shlex.quote(inp.target)
        return f"searchsploit --json {query}"

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse searchsploit JSON output into a normalised list of exploits.

        Args:
            result: Raw execution result.

        Returns:
            Dict with ``exploits`` list. Each entry has ``title``, ``path``,
            ``type``, ``platform``, ``date_published``.
        """
        raw = result.stdout.strip()
        if not raw:
            return {"exploits": []}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {"exploits": [], "error": "json_parse_failed", "raw": raw[:500]}

        entries: list[Any] = []
        if isinstance(data, dict):
            entries = (
                data.get("RESULTS_EXPLOIT") or data.get("results") or data.get("EXPLOITS") or []
            )
        elif isinstance(data, list):
            entries = data

        exploits: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            exploits.append(
                {
                    "title": entry.get("Title") or entry.get("title", ""),
                    "path": entry.get("Path") or entry.get("path", ""),
                    "type": entry.get("Type") or entry.get("type", ""),
                    "platform": entry.get("Platform") or entry.get("platform", ""),
                    "date_published": entry.get("Date_Published") or entry.get("date", ""),
                }
            )
        return {"exploits": exploits}
