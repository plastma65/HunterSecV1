"""Nmap port scanner wrapper.

# This module handles offensive primitive: network port scanning.
# Safety: command goes through SafetyFilter + SandboxExecutor.
# Test targets: RFC 5737 reserved (192.0.2.x, 198.51.100.x, 203.0.113.x)
#
# NOTE: -sS (raw SYN scan) is intentionally excluded — it requires root
# privileges that are not available in the rootless Docker sandbox.
# -sV (version detection) covers the use case without requiring root.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from huntersec.tools.base import BaseTool, RiskLevel, ToolCategory, ToolInput, ToolResult


class NmapTool(BaseTool):
    """Nmap TCP port and service version scanner.

    Outputs XML to stdout (``-oX -``) for reliable machine-readable parsing.
    Never uses ``-sS`` (raw SYN requires root/cap_net_raw).
    """

    name = "nmap"
    category = ToolCategory.RECON
    risk_level = RiskLevel.ACTIVE

    def build_command(self, inp: ToolInput) -> str:
        """Build an nmap command with XML output.

        Args:
            inp: Tool input; ``inp.args.get("flags")`` overrides default flags.

        Returns:
            nmap command string with ``-oX -`` appended for XML stdout output.
        """
        flags = inp.args.get("flags", "-sV -sC -T4 --open")
        return f"nmap {flags} -oX - {inp.target}"

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        """Parse nmap XML output into structured host/port/service data.

        Args:
            result: Raw execution result from the sandbox.

        Returns:
            Dict with ``hosts`` list. Each host has ``address``, ``state``,
            and ``ports`` (list of open port dicts with service details).
            Returns ``{"error": "…", "raw": "…"}`` on parse failure.
        """
        if not result.stdout.strip():
            return {"hosts": [], "error": "empty output"}
        try:
            root = ET.fromstring(result.stdout)  # noqa: S314 — nmap XML is sandbox-generated, not network-received
        except ET.ParseError as exc:
            return {"hosts": [], "error": str(exc), "raw": result.stdout[:2000]}

        hosts: list[dict[str, Any]] = []
        for host_el in root.findall("host"):
            state_el = host_el.find("status")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"

            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address")
            address = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

            ports: list[dict[str, Any]] = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    port_state_el = port_el.find("state")
                    port_state = (
                        port_state_el.get("state", "unknown")
                        if port_state_el is not None
                        else "unknown"
                    )
                    svc_el = port_el.find("service")
                    service: dict[str, str] = {}
                    if svc_el is not None:
                        service = {
                            "name": svc_el.get("name", ""),
                            "product": svc_el.get("product", ""),
                            "version": svc_el.get("version", ""),
                            "extrainfo": svc_el.get("extrainfo", ""),
                        }
                    ports.append(
                        {
                            "port": port_el.get("portid", ""),
                            "protocol": port_el.get("protocol", "tcp"),
                            "state": port_state,
                            "service": service,
                        }
                    )

            hosts.append({"address": address, "state": state, "ports": ports})

        return {"hosts": hosts}
