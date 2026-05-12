"""httpx HTTP probing wrapper.

# This module handles offensive primitive: HTTP service probing.
# Safety: command goes through SafetyFilter + SandboxExecutor.
# Test targets: RFC 5737 reserved (192.0.2.x, 198.51.100.x, 203.0.113.x)
"""

from __future__ import annotations

import json
from typing import Any

from huntersec.tools.base import BaseTool, RiskLevel, ToolCategory, ToolInput, ToolResult


class HttpxTool(BaseTool):
    """httpx HTTP probing and technology detection tool.

    Outputs one JSON object per line (JSONL) via ``-json -silent``.
    Collects status code, title, and detected technologies.
    """

    name = "httpx"
    category = ToolCategory.RECON
    risk_level = RiskLevel.PASSIVE

    def build_command(self, inp: ToolInput) -> str:
        """Build an httpx command for HTTP probing.

        Args:
            inp: Tool input containing the target.

        Returns:
            httpx command string producing JSONL to stdout.
        """
        target = inp.target
        return (
            f"httpx -u {target} -json -silent -tech-detect -title -status-code"
        )

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse httpx JSONL output into service information.

        Args:
            result: Raw execution result.

        Returns:
            Dict with ``services`` list.  Each entry has ``url``,
            ``status_code``, ``title``, and ``technologies``.
        """
        services: list[dict[str, Any]] = []
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            services.append(
                {
                    "url": entry.get("url", ""),
                    "status_code": entry.get("status-code"),
                    "title": entry.get("title", ""),
                    "technologies": entry.get("tech", []),
                    "content_length": entry.get("content-length"),
                }
            )
        return {"services": services}
