"""Web-focused enumeration sub-agent.

# This module handles offensive primitive: web vulnerability scanning.
# Safety: passive scan only by default, ACTIVE requires explicit flag.
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


class WebFindings(TypedDict):
    """Structured output of :meth:`WebAgent.run`."""

    directories: list[str]
    interesting_files: list[str]
    forms: list[dict]
    potential_vulns: list[str]
    errors: list[str]


# Files of high interest during web enumeration.
_INTERESTING_FILES = {
    "/robots.txt",
    "/.git",
    "/.git/",
    "/.git/config",
    "/.env",
    "/.htaccess",
    "/.htpasswd",
    "/backup",
    "/backup.zip",
    "/backup.tar",
    "/backup.tar.gz",
    "/admin",
    "/admin/",
    "/wp-admin",
    "/wp-admin/",
    "/wp-login.php",
    "/phpmyadmin",
    "/phpmyadmin/",
    "/server-status",
    "/server-info",
    "/.DS_Store",
    "/web.config",
    "/config.php",
    "/composer.json",
    "/package.json",
    "/sitemap.xml",
}


def _empty_findings() -> WebFindings:
    return WebFindings(
        directories=[],
        interesting_files=[],
        forms=[],
        potential_vulns=[],
        errors=[],
    )


class WebAgent:
    """Web-vuln focused enumeration: directory brute, header analysis.

    Skips entirely when the supplied :class:`ReconSummary` lists no web
    services — keeps the pipeline cheap on machines without HTTP exposure.

    Args:
        safety: SafetyFilter for command/target vetting.
        registry: ToolRegistry providing ``gobuster``, ``whatweb``, ``httpx``.
        audit: Audit logger.
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

    async def run(self, target: str, recon: ReconSummary) -> WebFindings:
        """Execute the web pipeline.

        Args:
            target: Target host/IP.
            recon: Output from :class:`ReconAgent`.  When ``web_services`` is
                empty the agent returns immediately with empty findings.

        Returns:
            Aggregated :class:`WebFindings`.
        """
        findings = _empty_findings()
        self._audit.log_event("subagent.web.start", {"target": target})

        if not recon.get("web_services"):
            log.info("subagent.web.skip", target=target, reason="no_web_services")
            self._audit.log_event(
                "subagent.web.skip", {"target": target, "reason": "no_web_services"}
            )
            return findings

        if recon.get("gobuster_ran"):
            # ReconAgent already ran gobuster against this target. Reuse its
            # results rather than burning a second wordlist pass — same scope,
            # same wordlist, doubles RoE noise on the target for no new data.
            log.info("subagent.web.gobuster.reuse", target=target)
            for path in recon.get("directories", []) or []:
                findings["directories"].append(path)
                if path in _INTERESTING_FILES or path.rstrip("/") in _INTERESTING_FILES:
                    findings["interesting_files"].append(path)
        else:
            await self._run_gobuster(target, findings)
        self._analyse_existing_data(recon, findings)

        self._audit.log_event(
            "subagent.web.end",
            {
                "target": target,
                "directories": len(findings["directories"]),
                "interesting_files": len(findings["interesting_files"]),
                "potential_vulns": len(findings["potential_vulns"]),
            },
        )
        return findings

    async def _run_gobuster(self, target: str, findings: WebFindings) -> None:
        web_target = target if target.startswith("http") else f"http://{target}"
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        command = f"gobuster dir -u {web_target} -w {wordlist} --no-color -q"
        decision = self._safety.check_command(command, target)
        if not decision["allowed"]:
            findings["errors"].append(f"gobuster blocked: {decision['reason']}")
            return
        try:
            result = await self._registry.run("gobuster", ToolInput(target=web_target))
        except Exception as exc:  # noqa: BLE001
            findings["errors"].append(f"gobuster failed: {exc!r}")
            return

        parsed = result.parsed or {}
        for entry in parsed.get("paths", []):
            path = entry.get("path", "")
            if not path:
                continue
            findings["directories"].append(path)
            if path in _INTERESTING_FILES or path.rstrip("/") in _INTERESTING_FILES:
                findings["interesting_files"].append(path)

    def _analyse_existing_data(self, recon: ReconSummary, findings: WebFindings) -> None:
        """Static heuristics on tech stack → potential_vulns hints."""
        for svc in recon.get("web_services", []):
            techs = svc.get("tech_stack", []) or []
            tech_str = " ".join(str(t).lower() for t in techs)
            if "wordpress" in tech_str:
                findings["potential_vulns"].append(
                    "WordPress detected — check wp-content/plugins, xmlrpc.php"
                )
            if "phpmyadmin" in tech_str:
                findings["potential_vulns"].append(
                    "phpMyAdmin detected — check default creds, version CVEs"
                )
            if "tomcat" in tech_str:
                findings["potential_vulns"].append(
                    "Apache Tomcat detected — check /manager/html default creds"
                )
            if "drupal" in tech_str:
                findings["potential_vulns"].append(
                    "Drupal detected — review version against Drupalgeddon CVEs"
                )
            if "jenkins" in tech_str:
                findings["potential_vulns"].append(
                    "Jenkins detected — check /script console exposure"
                )
