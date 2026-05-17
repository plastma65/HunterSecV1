"""Gobuster directory and DNS brute-forcing wrapper.

# This module handles offensive primitive: HTTP directory enumeration.
# Safety: command goes through SafetyFilter + SandboxExecutor.
# Test targets: RFC 5737 reserved (192.0.2.x, 198.51.100.x, 203.0.113.x)
"""

from __future__ import annotations

import re
from typing import Any

from huntersec.tools.base import BaseTool, RiskLevel, ToolCategory, ToolInput, ToolResult

_GOBUSTER_LINE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?",
    re.MULTILINE,
)


class GobusterTool(BaseTool):
    """Gobuster directory/file brute-forcer.

    Runs in ``dir`` mode by default (``dns`` mode available via args).
    Uses ``/usr/share/wordlists/dirb/common.txt`` as the default wordlist.
    """

    name = "gobuster"
    category = ToolCategory.RECON
    risk_level = RiskLevel.ACTIVE

    def build_command(self, inp: ToolInput) -> str:
        """Build a gobuster command in dir or dns mode.

        Args:
            inp: Tool input; ``inp.args.get("mode")`` selects ``dir`` or ``dns``.

        Returns:
            gobuster command string for the target.
        """
        mode = inp.args.get("mode", "dir")
        target = inp.target
        if not target.startswith("http"):
            target = f"http://{target}"

        wordlist = inp.args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        if mode == "dns":
            return f"gobuster dns -d {inp.target} -w {wordlist} --no-color -q"
        return f"gobuster dir -u {target} -w {wordlist} --no-color -q"

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse gobuster text output into a list of discovered paths.

        Args:
            result: Raw execution result.

        Returns:
            Dict with ``paths`` list (each entry has ``path``, ``status``, ``size``).
        """
        paths: list[dict[str, Any]] = []
        for m in _GOBUSTER_LINE.finditer(result.stdout):
            paths.append(
                {
                    "path": m.group("path"),
                    "status": int(m.group("status")),
                    "size": int(m.group("size")) if m.group("size") else None,
                }
            )
        return {"paths": paths}
