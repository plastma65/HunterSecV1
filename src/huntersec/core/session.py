"""Session manager — entry-point for running a complete agent session.

Usage::

    session = Session(
        target="192.0.2.1",
        scope_file=Path("configs/scope.yaml"),
        objective="recon",
    )
    report_path = asyncio.run(session.run())
"""

from __future__ import annotations

import uuid
from pathlib import Path

import structlog

from huntersec.core.graph import build_graph
from huntersec.core.state import AgentState
from huntersec.llm.router import LLMRouter
from huntersec.safety.audit import AuditLogger
from huntersec.safety.filter import SafetyFilter
from huntersec.sandbox.executor import SandboxExecutor
from huntersec.settings import LLMSettings, Settings
from huntersec.tools.registry import ToolRegistry, default_registry

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class Session:
    """Orchestrates a single autonomous security assessment session.

    Validates the target against the scope immediately on construction —
    raises before any LLM or sandbox resources are allocated.

    Args:
        target: IP, hostname, or URL to assess.
        scope_file: Path to the YAML scope definition.
        objective: Assessment objective (``"recon"`` | ``"exploit"`` | ``"ctf"``).
        settings: Application settings; defaults to :func:`~huntersec.settings.get_settings`.
        provider: LLM provider name (used to select the appropriate SDK adapter).

    Raises:
        ScopeNotConfiguredError: If the scope file does not exist.
        OutOfScopeError: If ``target`` is not authorised by the scope file.

    Example:
        >>> import asyncio
        >>> from pathlib import Path
        >>> from huntersec.core.session import Session
        >>> # session = Session("192.0.2.1", Path("configs/scope.yaml"))
        >>> # report = asyncio.run(session.run())
    """

    def __init__(
        self,
        target: str,
        scope_file: Path,
        objective: str = "recon",
        settings: Settings | None = None,
        provider: str = "anthropic",
    ) -> None:
        self._settings = settings or Settings()
        self._target = target
        self._scope_file = scope_file
        self._objective = objective
        self._provider = provider
        self._session_id = str(uuid.uuid4())

        # Validate scope FIRST — fail fast before allocating resources
        from huntersec.safety.scope import ScopeValidator

        self._scope_validator = ScopeValidator.load(scope_file)
        self._scope_validator.assert_in_scope(target)

        # Wire up components
        self._audit = AuditLogger(
            self._settings.safety.audit_log_dir,
            session_id=self._session_id,
        )
        self._sandbox = SandboxExecutor(self._settings.sandbox, self._audit)
        self._registry: ToolRegistry = default_registry(self._sandbox)
        self._llm = self._build_llm()
        self._safety = self._build_safety()

    def _build_llm(self) -> LLMRouter:
        """Instantiate LLMRouter based on configured provider."""
        llm_cfg: LLMSettings = self._settings.llm
        provider = self._provider

        if provider == "anthropic":
            from huntersec.llm.anthropic import AnthropicProvider

            prov = AnthropicProvider(
                api_key=llm_cfg.anthropic_api_key,
                default_model=llm_cfg.smart_model,
            )
        elif provider == "openai":
            from huntersec.llm.openai_provider import OpenAIProvider

            prov = OpenAIProvider(
                api_key=llm_cfg.openai_api_key,
                default_model=llm_cfg.smart_model,
            )
        else:
            from huntersec.llm.ollama import OllamaProvider

            prov = OllamaProvider(
                host=llm_cfg.ollama_host,
                default_model=llm_cfg.local_model,
            )

        return LLMRouter(
            [prov],
            token_budget=llm_cfg.token_budget_per_session,
        )

    def _build_safety(self) -> SafetyFilter:
        """Construct SafetyFilter from settings and the already-loaded scope."""
        from huntersec.safety.blocklist import BlocklistChecker
        from huntersec.safety.ratelimit import RateLimiter

        safety_cfg = self._settings.safety
        bl_path = safety_cfg.blocklist_file if safety_cfg.blocklist_file.exists() else None
        blocklist = BlocklistChecker.load(bl_path)
        ratelimiter = RateLimiter(
            global_rps=safety_cfg.rate_limit_global_rps,
            per_target_rps=safety_cfg.rate_limit_per_target_rps,
        )
        return SafetyFilter(self._scope_validator, blocklist, ratelimiter, self._audit)

    async def run(self) -> Path:
        """Execute the full agent session and return the path to the report.

        Returns:
            Path of the generated markdown report.

        Raises:
            RuntimeError: If the session ends in error status.
        """
        self._audit.log_event(
            "session.start",
            {
                "target": self._target,
                "scope_file": str(self._scope_file),
                "objective": self._objective,
                "provider": self._provider,
            },
        )
        log.info(
            "session.start",
            session_id=self._session_id,
            target=self._target,
            objective=self._objective,
        )

        initial_state: AgentState = {
            "session_id": self._session_id,
            "target": self._target,
            "scope_file": self._scope_file,
            "objective": self._objective,
            "plan": [],
            "current_step_index": 0,
            "tool_outputs": [],
            "findings": [],
            "report_path": None,
            "token_usage": 0,
            "status": "planning",
            "error": None,
            "loop_count": 0,
            "validation_decision": "",
        }

        compiled = build_graph(self._llm, self._registry, self._safety, self._audit)
        final_state: AgentState = await compiled.ainvoke(initial_state)

        self._audit.log_event(
            "session.end",
            {
                "target": self._target,
                "status": final_state.get("status"),
                "findings": len(final_state.get("findings", [])),
                "token_usage": final_state.get("token_usage", 0),
                "report_path": str(final_state.get("report_path", "")),
            },
        )

        if final_state.get("status") == "error":
            raise RuntimeError(
                f"Session ended in error: {final_state.get('error', 'unknown error')}"
            )

        report_path = final_state.get("report_path")
        if report_path is None:
            raise RuntimeError("Session completed but report_path is None.")

        log.info(
            "session.done",
            session_id=self._session_id,
            report=str(report_path),
            findings=len(final_state.get("findings", [])),
        )
        return Path(report_path)
