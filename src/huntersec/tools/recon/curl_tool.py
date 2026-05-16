"""curl — HTTP header probing wrapper.

# This module handles offensive primitive: HTTP header probing.
# Safety: command goes through SafetyFilter + SandboxExecutor.
# Test targets: RFC 5737 reserved (192.0.2.x, 198.51.100.x, 203.0.113.x)
"""

from __future__ import annotations

import re
from typing import Any

from huntersec.tools.base import BaseTool, RiskLevel, ToolCategory, ToolInput, ToolResult

_STATUS_LINE = re.compile(r"^HTTP/[\d.]+\s+(\d{3})\s*(.*)$")
_HEADER_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9\-]+)\s*:\s*(.*)$")


class CurlTool(BaseTool):
    """Lightweight HTTP header probe using ``curl -s -I -L``.

    Follows redirects (``-L``) and dumps response headers only (``-I``),
    so the wrapper stays passive — no body bytes are fetched.
    """

    name = "curl"
    category = ToolCategory.RECON
    risk_level = RiskLevel.PASSIVE

    def build_command(self, inp: ToolInput) -> str:
        """Build a curl HEAD probe command.

        Args:
            inp: Tool input.  Target may be a bare host (``http://`` prepended)
                or a full URL.  ``inp.args.get("flags")`` overrides defaults.

        Returns:
            curl command string.
        """
        url = inp.target
        if not url.startswith(("http://", "https://", "ftp://")):
            url = f"http://{url}"
        flags = inp.args.get("flags", "-s -I -L --max-time 10")
        return f"curl {flags} {url}"

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse curl ``-I`` output into a list of redirect hops.

        Each blank line in the output begins a new hop — useful when ``-L``
        follows redirects through multiple servers.

        Args:
            result: Raw execution result.

        Returns:
            Dict with ``hops`` (list of {status, reason, headers, server,
            content_type}) plus convenience fields for the final hop:
            ``status``, ``server``, ``content_type``.
        """
        hops: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None

        for raw_line in result.stdout.splitlines():
            line = raw_line.rstrip("\r")
            stripped = line.strip()

            status_match = _STATUS_LINE.match(stripped)
            if status_match:
                current = {
                    "status": int(status_match.group(1)),
                    "reason": status_match.group(2).strip(),
                    "headers": {},
                }
                hops.append(current)
                continue

            if not stripped:
                # blank line — boundary between hops
                current = None
                continue

            if current is None:
                continue

            header_match = _HEADER_LINE.match(stripped)
            if header_match:
                name = header_match.group(1).lower()
                value = header_match.group(2).strip()
                current["headers"][name] = value

        final = hops[-1] if hops else {}
        return {
            "hops": hops,
            "status": final.get("status"),
            "server": final.get("headers", {}).get("server", ""),
            "content_type": final.get("headers", {}).get("content-type", ""),
            "redirects": max(len(hops) - 1, 0),
        }
