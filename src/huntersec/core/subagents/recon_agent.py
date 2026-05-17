"""Reconnaissance sub-agent — wraps nmap/whatweb/httpx/gobuster.

# This module handles offensive primitive: reconnaissance automation.
# Safety: all targets validated against scope before execution.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NotRequired, TypedDict

import structlog

from huntersec.tools.base import ToolInput

if TYPE_CHECKING:
    from huntersec.safety.audit import AuditLogger
    from huntersec.safety.filter import SafetyFilter
    from huntersec.tools.registry import ToolRegistry

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class ReconSummary(TypedDict):
    """Structured output of :meth:`ReconAgent.run`."""

    target: str
    open_ports: list[dict]  # {port, protocol, service, version}
    web_services: list[dict]  # {url, title, tech_stack, status_code}
    hostnames: list[str]
    os_guess: str | None
    errors: list[str]
    # Paths discovered by gobuster during recon; consumed by WebAgent so the
    # same wordlist scan isn't repeated downstream. Marked NotRequired to
    # keep backwards compatibility with summaries built before this field
    # existed (e.g. legacy fixtures).
    directories: NotRequired[list[str]]
    gobuster_ran: NotRequired[bool]


_WEB_PORTS = {"80", "443", "8000", "8080", "8443"}


def _empty_summary(target: str) -> ReconSummary:
    return ReconSummary(
        target=target,
        open_ports=[],
        web_services=[],
        hostnames=[],
        os_guess=None,
        errors=[],
    )


class ReconAgent:
    """Run nmap → whatweb → httpx → gobuster in sequence and aggregate findings.

    Each step fails gracefully — a failed tool appends to ``errors`` and the
    pipeline continues with the data collected so far.

    Args:
        safety: :class:`~huntersec.safety.filter.SafetyFilter` used to vet
            every tool/target pair before execution.
        registry: :class:`~huntersec.tools.registry.ToolRegistry` providing
            ``nmap``, ``whatweb``, ``httpx``, ``gobuster``.
        audit: Audit logger receiving lifecycle events.

    Example:
        >>> from huntersec.core.subagents.recon_agent import ReconAgent
        >>> # agent = ReconAgent(safety, registry, audit)
        >>> # summary = await agent.run("192.0.2.1")
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

    async def run(self, target: str) -> ReconSummary:
        """Execute the recon pipeline against ``target``.

        Args:
            target: IP, hostname, or URL to enumerate.

        Returns:
            Aggregated :class:`ReconSummary`.  Always returns — failures
            are reported via the ``errors`` field.
        """
        summary = _empty_summary(target)
        self._audit.log_event("subagent.recon.start", {"target": target})
        log.info("subagent.recon.start", target=target)

        await self._run_nmap(target, summary)
        await self._run_whatweb(target, summary)
        await self._run_httpx(target, summary)
        await self._run_gobuster(target, summary)

        self._audit.log_event(
            "subagent.recon.end",
            {
                "target": target,
                "open_ports": len(summary["open_ports"]),
                "web_services": len(summary["web_services"]),
                "errors": len(summary["errors"]),
            },
        )
        log.info(
            "subagent.recon.end",
            target=target,
            ports=len(summary["open_ports"]),
            web=len(summary["web_services"]),
        )
        return summary

    # ── Tool steps ────────────────────────────────────────────────────────────

    async def _run_nmap(self, target: str, summary: ReconSummary) -> None:
        command = f"nmap -sV -sC -T4 --open -oX - {target}"
        decision = self._safety.check_command(command, target)
        if not decision["allowed"]:
            summary["errors"].append(f"nmap blocked: {decision['reason']}")
            return
        try:
            result = await self._registry.run("nmap", ToolInput(target=target))
        except Exception as exc:  # noqa: BLE001 — collect & continue
            summary["errors"].append(f"nmap failed: {exc!r}")
            log.warning("subagent.recon.nmap.error", target=target, exc=repr(exc))
            return

        parsed = result.parsed or {}
        for host in parsed.get("hosts", []):
            for port_info in host.get("ports", []):
                if port_info.get("state") != "open":
                    continue
                svc = port_info.get("service") or {}
                summary["open_ports"].append(
                    {
                        "port": port_info.get("port", ""),
                        "protocol": port_info.get("protocol", "tcp"),
                        "service": svc.get("name", ""),
                        "version": (svc.get("product", "") + " " + svc.get("version", "")).strip(),
                    }
                )

    async def _run_whatweb(self, target: str, summary: ReconSummary) -> None:
        if not self._has_web_port(summary):
            return
        web_target = target if target.startswith("http") else f"http://{target}"
        command = f"whatweb --log-json=- {web_target}"
        decision = self._safety.check_command(command, target)
        if not decision["allowed"]:
            summary["errors"].append(f"whatweb blocked: {decision['reason']}")
            return
        try:
            result = await self._registry.run("whatweb", ToolInput(target=web_target))
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"whatweb failed: {exc!r}")
            return

        parsed = result.parsed or {}
        techs = parsed.get("technologies", {})
        summary["web_services"].append(
            {
                "url": parsed.get("target", web_target),
                "title": "",
                "tech_stack": sorted(techs.keys()),
                "status_code": parsed.get("http_status"),
            }
        )

    async def _run_httpx(self, target: str, summary: ReconSummary) -> None:
        if not self._has_web_port(summary):
            return
        command = f"httpx -u {target} -json -silent -tech-detect -title -status-code"
        decision = self._safety.check_command(command, target)
        if not decision["allowed"]:
            summary["errors"].append(f"httpx blocked: {decision['reason']}")
            return
        try:
            result = await self._registry.run("httpx", ToolInput(target=target))
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"httpx failed: {exc!r}")
            return

        parsed = result.parsed or {}
        for svc in parsed.get("services", []):
            summary["web_services"].append(
                {
                    "url": svc.get("url", ""),
                    "title": svc.get("title", ""),
                    "tech_stack": svc.get("technologies", []),
                    "status_code": svc.get("status_code"),
                }
            )

    async def _run_gobuster(self, target: str, summary: ReconSummary) -> None:
        if not self._has_web_port(summary):
            return
        web_target = target if target.startswith("http") else f"http://{target}"
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        command = f"gobuster dir -u {web_target} -w {wordlist} --no-color -q"
        decision = self._safety.check_command(command, target)
        if not decision["allowed"]:
            summary["errors"].append(f"gobuster blocked: {decision['reason']}")
            return
        try:
            result = await self._registry.run("gobuster", ToolInput(target=web_target))
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"gobuster failed: {exc!r}")
            return

        # Cache results on the summary so WebAgent doesn't re-run gobuster.
        summary["gobuster_ran"] = True
        directories = summary.setdefault("directories", [])
        parsed = result.parsed or {}
        for entry in parsed.get("paths", []):
            path = entry.get("path", "")
            if path:
                directories.append(path)

    def _has_web_port(self, summary: ReconSummary) -> bool:
        # No nmap data → no evidence of a web port → skip web tools. We used
        # to "be optimistic and probe anyway", which produced synthetic
        # ``web_services`` entries on machines that didn't actually expose
        # HTTP — see E2E test report Issue 3.
        return any(str(p.get("port")) in _WEB_PORTS for p in summary["open_ports"])
