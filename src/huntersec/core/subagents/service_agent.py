"""Service-specific enumeration sub-agent (read-only).

# This module handles offensive primitive: service-specific enumeration.
# Safety: read-only operations only (enumeration, not exploitation).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

import structlog

from huntersec.tools.base import ToolInput

if TYPE_CHECKING:
    from huntersec.core.subagents.recon_agent import ReconSummary
    from huntersec.safety.audit import AuditLogger
    from huntersec.safety.filter import SafetyFilter
    from huntersec.tools.registry import ToolRegistry

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class ServiceFindings(TypedDict):
    """Structured output of :meth:`ServiceAgent.run`."""

    service_details: dict[str, dict]
    anonymous_access: list[str]
    version_info: dict[str, str]
    errors: list[str]


def _empty_findings() -> ServiceFindings:
    return ServiceFindings(
        service_details={},
        anonymous_access=[],
        version_info={},
        errors=[],
    )


# Map well-known ports to handler tags (no exploit attempts).
_DISPATCH = {
    "21": "ftp",
    "22": "ssh",
    "80": "http",
    "139": "smb",
    "443": "https",
    "445": "smb",
    "3306": "mysql",
    "5432": "postgres",
}


class ServiceAgent:
    """Dispatch protocol-specific *enumeration* (never exploitation).

    Only invokes tools already registered in :class:`ToolRegistry`.  When a
    service has no registered enumerator the port is recorded with a stub
    entry so callers still see it surfaced.
    """

    def __init__(
        self,
        safety: SafetyFilter,
        registry: ToolRegistry,
        audit: AuditLogger,
    ) -> None:
        self._safety = safety
        self._registry = registry
        self._audit = audit

    async def run(self, target: str, recon: ReconSummary) -> ServiceFindings:
        """Run enumeration handlers for every recognised open port.

        Args:
            target: Target host/IP.
            recon: Output of :class:`ReconAgent`.

        Returns:
            :class:`ServiceFindings`.
        """
        findings = _empty_findings()
        self._audit.log_event("subagent.service.start", {"target": target})

        for port_info in recon.get("open_ports", []):
            port = str(port_info.get("port", ""))
            handler = _DISPATCH.get(port)
            findings["version_info"][port] = port_info.get("version", "") or ""
            if handler is None:
                continue
            await self._dispatch(handler, target, port, port_info, findings)

        self._audit.log_event(
            "subagent.service.end",
            {
                "target": target,
                "anonymous_access": len(findings["anonymous_access"]),
                "services": len(findings["service_details"]),
            },
        )
        return findings

    async def _dispatch(
        self,
        handler: str,
        target: str,
        port: str,
        port_info: dict,
        findings: ServiceFindings,
    ) -> None:
        if handler == "ftp":
            await self._enum_ftp(target, port, findings)
        elif handler == "ssh":
            self._enum_ssh(target, port, port_info, findings)
        elif handler in {"http", "https"}:
            self._enum_http(target, port, handler, findings)
        elif handler == "smb":
            await self._enum_smb(target, port, findings)
        elif handler == "mysql":
            self._enum_mysql(target, port, findings)
        elif handler == "postgres":
            self._enum_postgres(target, port, findings)

    async def _enum_ftp(self, target: str, port: str, findings: ServiceFindings) -> None:
        # Anonymous FTP probe — read-only LIST.  Uses curl since it is
        # already in the registry; falls back gracefully when missing.
        command = f"curl -s --max-time 10 ftp://anonymous:anonymous@{target}:{port}/"
        decision = self._safety.check_command(command, target)
        if not decision["allowed"]:
            findings["errors"].append(f"ftp probe blocked: {decision['reason']}")
            return
        if "curl" not in self._registry.list_tools():
            findings["service_details"][f"ftp:{port}"] = {"status": "no_curl_tool"}
            return
        try:
            result = await self._registry.run(
                "curl",
                ToolInput(target=f"ftp://{target}:{port}/", args={"flags": "-s"}),
            )
        except Exception as exc:  # noqa: BLE001
            findings["errors"].append(f"ftp probe failed: {exc!r}")
            return

        details = {"exit_code": result.exit_code, "bytes_seen": len(result.stdout)}
        findings["service_details"][f"ftp:{port}"] = details
        if result.exit_code == 0:
            findings["anonymous_access"].append(f"ftp:{port}")

    def _enum_ssh(self, target: str, port: str, port_info: dict, findings: ServiceFindings) -> None:
        findings["service_details"][f"ssh:{port}"] = {
            "banner": port_info.get("version", ""),
            "note": "version_only — no auth attempt",
        }

    def _enum_http(self, target: str, port: str, handler: str, findings: ServiceFindings) -> None:
        scheme = "https" if handler == "https" else "http"
        findings["service_details"][f"{handler}:{port}"] = {
            "url": f"{scheme}://{target}:{port}/",
            "note": "delegate to WebAgent",
        }

    async def _enum_smb(self, target: str, port: str, findings: ServiceFindings) -> None:
        if "enum4linux-ng" not in self._registry.list_tools():
            findings["service_details"][f"smb:{port}"] = {"status": "no_enum4linux_tool"}
            return
        command = f"enum4linux-ng -A {target}"
        decision = self._safety.check_command(command, target)
        if not decision["allowed"]:
            findings["errors"].append(f"smb probe blocked: {decision['reason']}")
            return
        try:
            result = await self._registry.run("enum4linux-ng", ToolInput(target=target))
        except Exception as exc:  # noqa: BLE001
            findings["errors"].append(f"smb probe failed: {exc!r}")
            return
        parsed = result.parsed or {}
        findings["service_details"][f"smb:{port}"] = {
            "users": parsed.get("users", []),
            "shares": parsed.get("shares", []),
        }
        if parsed.get("shares"):
            findings["anonymous_access"].append(f"smb:{port}")

    def _enum_mysql(self, target: str, port: str, findings: ServiceFindings) -> None:
        findings["service_details"][f"mysql:{port}"] = {
            "note": "anonymous MySQL probe not implemented — manual check required"
        }

    def _enum_postgres(self, target: str, port: str, findings: ServiceFindings) -> None:
        findings["service_details"][f"postgres:{port}"] = {
            "note": "anonymous PostgreSQL probe not implemented — manual check required"
        }
