"""enum4linux-ng SMB enumeration wrapper.

# This module handles offensive primitive: SMB null-session enumeration.
# Safety: command goes through SafetyFilter + SandboxExecutor.
# Test targets: RFC 5737 reserved (192.0.2.x, 198.51.100.x, 203.0.113.x)
"""

from __future__ import annotations

import json
from typing import Any

from huntersec.tools.base import BaseTool, RiskLevel, ToolCategory, ToolInput, ToolResult


class Enum4linuxTool(BaseTool):
    """enum4linux-ng SMB / NetBIOS / LDAP enumerator.

    Uses ``-A`` (do all simple checks) and ``-oJ`` for JSON output to a
    fixed path inside the sandbox tmpfs.  Falls back to parsing whatever
    JSON appears on stdout when the output file is missing.
    """

    name = "enum4linux-ng"
    category = ToolCategory.RECON
    risk_level = RiskLevel.ACTIVE

    def build_command(self, inp: ToolInput) -> str:
        """Build enum4linux-ng command.

        Args:
            inp: Tool input.

        Returns:
            Command string writing JSON output to stdout via cat-after-run
            pattern is *not* used — we rely on ``-oJ -`` style emission,
            falling back to grepable text when unavailable.
        """
        return f"enum4linux-ng -A {inp.target}"

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse enum4linux-ng output.

        Attempts JSON parsing first; on failure performs lightweight
        heuristic extraction of users and shares from the text output.

        Args:
            result: Raw execution result.

        Returns:
            Dict with ``users``, ``shares``, ``policies``, ``domain`` keys.
        """
        raw = result.stdout.strip()
        if not raw:
            return {"users": [], "shares": [], "policies": {}, "domain": None}

        # Try JSON output first
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return self._parse_text(raw)

        users = self._extract_users(data)
        shares = self._extract_shares(data)
        return {
            "users": users,
            "shares": shares,
            "policies": data.get("policies", {}) if isinstance(data, dict) else {},
            "domain": (data.get("domain") if isinstance(data, dict) else None),
        }

    @staticmethod
    def _extract_users(data: Any) -> list[str]:
        if not isinstance(data, dict):
            return []
        block = data.get("users") or data.get("Users") or {}
        if isinstance(block, dict):
            return sorted(block.keys())
        if isinstance(block, list):
            return [str(u) for u in block]
        return []

    @staticmethod
    def _extract_shares(data: Any) -> list[dict]:
        if not isinstance(data, dict):
            return []
        block = data.get("shares") or data.get("Shares") or {}
        if isinstance(block, dict):
            return [
                {"name": name, **(detail if isinstance(detail, dict) else {})}
                for name, detail in block.items()
            ]
        if isinstance(block, list):
            return [s if isinstance(s, dict) else {"name": str(s)} for s in block]
        return []

    @staticmethod
    def _parse_text(raw: str) -> dict[str, Any]:
        users: list[str] = []
        shares: list[dict] = []
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("user:") or stripped.startswith("User:"):
                _, _, name = stripped.partition(":")
                name = name.strip()
                if name:
                    users.append(name)
            elif stripped.startswith("//") and " " in stripped:
                # Heuristic: //host/share  type  comment
                parts = stripped.split()
                if parts:
                    shares.append({"name": parts[0]})
        return {"users": users, "shares": shares, "policies": {}, "domain": None}
