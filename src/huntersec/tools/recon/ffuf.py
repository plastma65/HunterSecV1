"""ffuf web fuzzer wrapper.

# This module handles offensive primitive: HTTP parameter and path fuzzing.
# Safety: command goes through SafetyFilter + SandboxExecutor.
# Test targets: RFC 5737 reserved (192.0.2.x, 198.51.100.x, 203.0.113.x)
"""

from __future__ import annotations

import re
from typing import Any

from huntersec.tools.base import BaseTool, RiskLevel, ToolCategory, ToolInput, ToolResult

_FFUF_LINE = re.compile(
    r"^(?P<word>\S+)\s+\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+)",
    re.MULTILINE,
)


class FfufTool(BaseTool):
    """ffuf web fuzzer for directory and parameter discovery.

    Uses the seclists common wordlist with ``-s`` (silent/no-banner) and
    ``-noninteractive`` flags so output is machine-parseable text.
    """

    name = "ffuf"
    category = ToolCategory.RECON
    risk_level = RiskLevel.ACTIVE

    def build_command(self, inp: ToolInput) -> str:
        """Build an ffuf command targeting FUZZ in the URL path.

        Args:
            inp: Tool input; ``inp.args.get("wordlist")`` overrides the default.

        Returns:
            ffuf command string producing text output to stdout.
        """
        target = inp.target
        if not target.startswith("http"):
            target = f"http://{target}"

        wordlist = inp.args.get(
            "wordlist",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        )
        return f"ffuf -u {target}/FUZZ -w {wordlist} -s -noninteractive"

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse ffuf text output into discovered paths with status codes.

        Args:
            result: Raw execution result.

        Returns:
            Dict with ``results`` list (each entry has ``word``, ``status``, ``size``).
        """
        found: list[dict[str, Any]] = []
        for m in _FFUF_LINE.finditer(result.stdout):
            found.append(
                {
                    "word": m.group("word"),
                    "status": int(m.group("status")),
                    "size": int(m.group("size")),
                }
            )
        # Also handle plain-word output when -s produces only matched words
        if not found and result.stdout.strip():
            for line in result.stdout.splitlines():
                word = line.strip()
                if word:
                    found.append({"word": word, "status": None, "size": None})
        return {"results": found}
