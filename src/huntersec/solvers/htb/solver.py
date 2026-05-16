"""HTB / THM machine solver orchestrator.

# This module handles offensive primitive: HTB machine solving automation.
# Safety: scope must be configured to HTB VPN subnet before running.
"""

from __future__ import annotations

import re
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal, TypedDict

import structlog

from huntersec.core.subagents import ReconAgent, ServiceAgent, WebAgent
from huntersec.exceptions import OutOfScopeError, ScopeNotConfiguredError
from huntersec.safety.audit import AuditLogger
from huntersec.safety.filter import SafetyFilter
from huntersec.sandbox.executor import SandboxExecutor
from huntersec.settings import SafetySettings, Settings
from huntersec.tools.registry import ToolRegistry, default_registry

if TYPE_CHECKING:
    from huntersec.core.subagents.recon_agent import ReconSummary
    from huntersec.core.subagents.service_agent import ServiceFindings
    from huntersec.core.subagents.web_agent import WebFindings

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


# Strict CTF/HTB flag format: exactly 32 lowercase hex chars (MD5-like).
# Word-boundary anchors prevent matching mid-string in unrelated hex blobs.
FLAG_PATTERN = re.compile(r"\b[a-f0-9]{32}\b")

# MD5("") — false positive we explicitly reject.
_EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"


class SolveResult(TypedDict):
    """Outcome of :meth:`HTBSolver.solve`."""

    target: str
    user_flag: str | None
    root_flag: str | None
    report_path: Path | None
    duration_seconds: float
    steps_taken: int
    status: Literal["solved", "partial", "failed", "timeout"]


def extract_flags(text: str) -> list[str]:
    """Extract 32-hex-char flag candidates from arbitrary text.

    Args:
        text: Any tool stdout/stderr blob.

    Returns:
        Deduplicated list of flag candidates, with the empty-string MD5
        filtered out (common false positive on empty file hashes).
    """
    candidates = FLAG_PATTERN.findall(text or "")
    seen: set[str] = set()
    flags: list[str] = []
    for c in candidates:
        if c == _EMPTY_MD5 or c in seen:
            continue
        seen.add(c)
        flags.append(c)
    return flags


class HTBSolver:
    """Orchestrate a recon → web → service pass against an HTB/THM machine.

    The solver is intentionally *non-exploitative* in this Phase 2 cut: it
    runs structured enumeration and scans every captured tool output for
    flag-shaped strings (any caught flag is a free win — e.g. low-hanging
    fruit on intentionally vulnerable lab boxes).

    Args:
        target_ip: Host/IP of the machine.
        scope_file: Path to scope YAML defining the authorised subnet.
        settings: Optional :class:`~huntersec.settings.Settings`; defaults to
            an instance configured with ``scope_file``.

    Raises:
        ScopeNotConfiguredError: If the scope file is missing.
        OutOfScopeError: If ``target_ip`` falls outside the scope.

    Example:
        >>> from pathlib import Path
        >>> from huntersec.solvers.htb.solver import HTBSolver
        >>> # solver = HTBSolver("10.10.11.42", Path("configs/scope.yaml"))
        >>> # result = await solver.solve()
    """

    DEFAULT_TIMEOUT_SECONDS = 1800  # 30 minutes hard cap per run

    def __init__(
        self,
        target_ip: str,
        scope_file: Path,
        settings: Settings | None = None,
    ) -> None:
        self._target = target_ip
        self._scope_file = scope_file
        self._session_id = str(uuid.uuid4())
        self._settings = settings or Settings(
            safety=SafetySettings(scope_file=scope_file)
        )

        # Validate scope FIRST — no resources allocated otherwise.
        from huntersec.safety.scope import ScopeValidator

        self._scope_validator = ScopeValidator.load(scope_file)
        self._scope_validator.assert_in_scope(target_ip)

        # Wire components
        self._audit = AuditLogger(
            self._settings.safety.audit_log_dir,
            session_id=self._session_id,
        )
        self._sandbox = SandboxExecutor(self._settings.sandbox, self._audit)
        self._registry: ToolRegistry = default_registry(self._sandbox)
        self._safety = self._build_safety()

    @classmethod
    def from_components(
        cls,
        target_ip: str,
        scope_file: Path,
        safety: SafetyFilter,
        registry: ToolRegistry,
        audit: AuditLogger,
    ) -> HTBSolver:
        """Build a solver from already-constructed components (test helper).

        Bypasses real LLM / sandbox wiring — used by unit tests that supply
        :class:`~huntersec.sandbox.mock.MockSandboxExecutor` and a hand-rolled
        :class:`SafetyFilter`.
        """
        from huntersec.safety.scope import ScopeValidator

        instance = cls.__new__(cls)
        instance._target = target_ip
        instance._scope_file = scope_file
        instance._session_id = str(uuid.uuid4())
        instance._settings = Settings(safety=SafetySettings(scope_file=scope_file))
        instance._scope_validator = ScopeValidator.load(scope_file)
        instance._scope_validator.assert_in_scope(target_ip)
        instance._audit = audit
        instance._sandbox = None  # type: ignore[assignment]
        instance._registry = registry
        instance._safety = safety
        return instance

    def _build_safety(self) -> SafetyFilter:
        from huntersec.safety.blocklist import BlocklistChecker
        from huntersec.safety.ratelimit import RateLimiter

        cfg = self._settings.safety
        bl_path = cfg.blocklist_file if cfg.blocklist_file.exists() else None
        blocklist = BlocklistChecker.load(bl_path)
        ratelimiter = RateLimiter(
            global_rps=cfg.rate_limit_global_rps,
            per_target_rps=cfg.rate_limit_per_target_rps,
        )
        return SafetyFilter(self._scope_validator, blocklist, ratelimiter, self._audit)

    # ── Public API ────────────────────────────────────────────────────────────

    async def solve(self) -> SolveResult:
        """Run the full enumeration pipeline against the target.

        Returns:
            :class:`SolveResult` summarising flags found and report path.
        """
        start = time.monotonic()
        self._audit.log_event(
            "solver.htb.start",
            {"target": self._target, "session_id": self._session_id},
        )
        log.info("solver.htb.start", target=self._target)

        steps_taken = 0
        flags_found: list[str] = []
        all_outputs: list[str] = []

        try:
            recon: ReconSummary = await ReconAgent(
                self._safety, self._registry, self._audit
            ).run(self._target)
            steps_taken += 1
            all_outputs.append(self._dump_recon(recon))

            web: WebFindings = await WebAgent(
                self._safety, self._registry, self._audit
            ).run(self._target, recon)
            steps_taken += 1
            all_outputs.append(self._dump_web(web))

            svc: ServiceFindings = await ServiceAgent(
                self._safety, self._registry, self._audit
            ).run(self._target, recon)
            steps_taken += 1
            all_outputs.append(self._dump_service(svc))

            for blob in all_outputs:
                flags_found.extend(extract_flags(blob))

            report_path = self._write_report(recon, web, svc, flags_found)

        except (OutOfScopeError, ScopeNotConfiguredError) as exc:
            self._audit.log_event(
                "solver.htb.scope_violation",
                {"target": self._target, "reason": str(exc)},
            )
            return SolveResult(
                target=self._target,
                user_flag=None,
                root_flag=None,
                report_path=None,
                duration_seconds=round(time.monotonic() - start, 3),
                steps_taken=steps_taken,
                status="failed",
            )

        duration = round(time.monotonic() - start, 3)
        status: Literal["solved", "partial", "failed", "timeout"]
        user_flag = flags_found[0] if flags_found else None
        root_flag = flags_found[1] if len(flags_found) > 1 else None

        if user_flag and root_flag:
            status = "solved"
        elif user_flag:
            status = "partial"
        else:
            status = "failed"

        self._audit.log_event(
            "solver.htb.end",
            {
                "target": self._target,
                "status": status,
                "flags": len(flags_found),
                "duration_seconds": duration,
            },
        )
        log.info(
            "solver.htb.end",
            target=self._target,
            status=status,
            flags=len(flags_found),
            duration=duration,
        )

        return SolveResult(
            target=self._target,
            user_flag=user_flag,
            root_flag=root_flag,
            report_path=report_path,
            duration_seconds=duration,
            steps_taken=steps_taken,
            status=status,
        )

    # ── Reporting helpers ─────────────────────────────────────────────────────

    def _dump_recon(self, recon: ReconSummary) -> str:
        return (
            f"open_ports={recon.get('open_ports')}\n"
            f"web_services={recon.get('web_services')}\n"
            f"errors={recon.get('errors')}\n"
        )

    def _dump_web(self, web: WebFindings) -> str:
        return (
            f"directories={web.get('directories')}\n"
            f"interesting_files={web.get('interesting_files')}\n"
            f"potential_vulns={web.get('potential_vulns')}\n"
        )

    def _dump_service(self, svc: ServiceFindings) -> str:
        return (
            f"service_details={svc.get('service_details')}\n"
            f"anonymous_access={svc.get('anonymous_access')}\n"
        )

    def _write_report(
        self,
        recon: ReconSummary,
        web: WebFindings,
        svc: ServiceFindings,
        flags: list[str],
    ) -> Path:
        report_dir = Path("data/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        path = report_dir / f"htb-{self._session_id}.md"

        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        ports = recon.get("open_ports", []) or []
        web_services = recon.get("web_services", []) or []
        interesting = web.get("interesting_files", []) or []
        anon = svc.get("anonymous_access", []) or []
        vulns = web.get("potential_vulns", []) or []

        port_lines = [
            f"- `{p.get('port')}/{p.get('protocol')}` — "
            f"{p.get('service')} {p.get('version')}".rstrip()
            for p in ports
        ] or ["_None detected._"]
        web_lines = [
            f"- `{s.get('url')}` [{s.get('status_code')}] {s.get('title')}".rstrip()
            for s in web_services
        ] or ["_None detected._"]
        interesting_lines = [f"- `{f}`" for f in interesting] or ["_None._"]
        anon_lines = [f"- {a}" for a in anon] or ["_None._"]
        vuln_lines = [f"- {v}" for v in vulns] or ["_None._"]
        flag_lines = [f"  - `{f}`" for f in flags[:4]]

        lines: list[str] = [
            f"# HTB Solver Report: {self._target}",
            f"_Generated: {now} | Session: {self._session_id}_",
            "",
            "## Status",
            f"- Flags found: {len(flags)}",
            *flag_lines,
            "",
            "## Open Ports",
            *port_lines,
            "",
            "## Web Services",
            *web_lines,
            "",
            "## Directories of Interest",
            *interesting_lines,
            "",
            "## Anonymous Access",
            *anon_lines,
            "",
            "## Potential Vulnerabilities",
            *vuln_lines,
            "",
            "---",
            "_Report generated by HunterSecV1 HTBSolver. Authorised testing only._",
        ]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path
