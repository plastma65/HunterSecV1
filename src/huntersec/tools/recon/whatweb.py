"""WhatWeb technology fingerprinting wrapper.

# This module handles offensive primitive: web technology fingerprinting.
# Safety: command goes through SafetyFilter + SandboxExecutor.
# Test targets: RFC 5737 reserved (192.0.2.x, 198.51.100.x, 203.0.113.x)
"""

from __future__ import annotations

import json
from typing import Any

from huntersec.tools.base import BaseTool, RiskLevel, ToolCategory, ToolInput, ToolResult


class WhatwebTool(BaseTool):
    """WhatWeb web technology fingerprinter.

    Outputs JSON via ``--log-json=-`` (stdout).  Falls back gracefully if
    WhatWeb outputs non-JSON text.
    """

    name = "whatweb"
    category = ToolCategory.RECON
    risk_level = RiskLevel.PASSIVE

    def build_command(self, inp: ToolInput) -> str:
        """Build a WhatWeb command with JSON stdout output.

        Args:
            inp: Tool input containing the target.

        Returns:
            WhatWeb command string writing JSON to stdout.
        """
        target = inp.target
        if not target.startswith("http"):
            target = f"http://{target}"
        return f"whatweb --log-json=- {target}"

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse WhatWeb JSON output into a tech-stack dictionary.

        Args:
            result: Raw execution result.

        Returns:
            Dict with ``technologies`` dict keyed by plugin name, plus
            ``http_status`` and ``target``.  Returns ``{"error": "…"}``
            on parse failure.
        """
        raw = result.stdout.strip()
        if not raw:
            return {"technologies": {}, "http_status": None}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # WhatWeb sometimes outputs non-JSON lines before the JSON array
            for raw_line in raw.splitlines():
                line = raw_line.strip()
                if line.startswith("["):
                    try:
                        data = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        pass
            else:
                return {"technologies": {}, "error": "json_parse_failed", "raw": raw[:500]}

        if not isinstance(data, list) or not data:
            return {"technologies": {}, "http_status": None}

        entry = data[0]
        plugins: dict[str, Any] = entry.get("plugins", {})
        # Flatten plugin data: name → {version, confidence}
        techs: dict[str, Any] = {}
        for plugin_name, plugin_data in plugins.items():
            version_list: list[str] = plugin_data.get("version", [])
            techs[plugin_name] = {
                "version": version_list[0] if version_list else None,
                "confidence": plugin_data.get("confidence", 0),
            }
        return {
            "target": entry.get("target", ""),
            "http_status": entry.get("http_status"),
            "technologies": techs,
        }
