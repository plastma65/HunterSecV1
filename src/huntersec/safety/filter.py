"""SafetyFilter — single authoritative entry-point for all action checks.

Every offensive action MUST be vetted through :meth:`SafetyFilter.check_command`
or :meth:`SafetyFilter.check_target` **before** reaching the sandbox.

Design contract:
* Fail-closed: any unhandled exception from a sub-component is treated as a
  denial and logged.  Never propagate errors to callers in a way that could be
  misread as "allowed".
* Audit-complete: every decision (allow **and** deny) is written to the audit
  log via :class:`~huntersec.safety.audit.AuditLogger`.
* Composable: the filter does not hard-code sub-components — they are injected,
  which makes unit testing straightforward.
"""

from __future__ import annotations

from typing import TypedDict

import structlog

from huntersec.exceptions import SafetyViolationError
from huntersec.safety.audit import AuditEvent, AuditLogger
from huntersec.safety.blocklist import BlocklistChecker
from huntersec.safety.ratelimit import RateLimiter
from huntersec.safety.scope import ScopeValidator
from huntersec.settings import SafetySettings

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class SafetyDecision(TypedDict):
    """Result of a :class:`SafetyFilter` check.

    Attributes:
        allowed: True iff the action is permitted.
        reason: Human-readable explanation of the decision.
        audit_event: The persisted audit row for this decision.
    """

    allowed: bool
    reason: str
    audit_event: AuditEvent


class SafetyFilter:
    """Compose scope, blocklist, and rate-limit checks into one allow/deny decision.

    Args:
        scope: Loaded and validated scope checker.
        blocklist: Compiled blocklist checker.
        ratelimiter: Configured token-bucket rate limiter.
        audit: Audit logger bound to the current session.

    Example:
        >>> from huntersec.safety import SafetyFilter, AuditLogger
        >>> from pathlib import Path
        >>> audit = AuditLogger(Path("data/audit"))
        >>> sf = SafetyFilter.from_settings(SafetySettings(), audit)
        >>> decision = sf.check_command("nmap -sV 192.0.2.1", "192.0.2.1")
        >>> assert decision["allowed"]
    """

    def __init__(
        self,
        scope: ScopeValidator,
        blocklist: BlocklistChecker,
        ratelimiter: RateLimiter,
        audit: AuditLogger,
    ) -> None:
        self._scope = scope
        self._blocklist = blocklist
        self._ratelimiter = ratelimiter
        self._audit = audit

    @classmethod
    def from_settings(cls, settings: SafetySettings, audit: AuditLogger) -> SafetyFilter:
        """Construct a :class:`SafetyFilter` from validated settings.

        Args:
            settings: Validated :class:`~huntersec.settings.SafetySettings`.
            audit: Audit logger for the current session.

        Returns:
            Fully configured :class:`SafetyFilter`.

        Raises:
            ScopeNotConfiguredError: If the scope file does not exist.
            pydantic.ValidationError: If scope/blocklist files are malformed.
        """
        scope = ScopeValidator.load(settings.scope_file)
        blocklist_path = settings.blocklist_file if settings.blocklist_file.exists() else None
        blocklist = BlocklistChecker.load(blocklist_path)
        ratelimiter = RateLimiter(
            global_rps=settings.rate_limit_global_rps,
            per_target_rps=settings.rate_limit_per_target_rps,
        )
        return cls(scope, blocklist, ratelimiter, audit)

    def check_target(self, target: str) -> SafetyDecision:
        """Check whether a target is authorized (scope + rate limit).

        Args:
            target: IP address, hostname, or URL to validate.

        Returns:
            :class:`SafetyDecision` — never raises; always returns a decision.
        """
        try:
            self._scope.assert_in_scope(target)
            self._ratelimiter.consume(target)
        except SafetyViolationError as exc:
            event = self._audit.log_event(
                "safety.deny.target",
                {"target": target, "reason": str(exc), "violation": type(exc).__name__},
            )
            log.warning("safety.deny.target", target=target, reason=str(exc))
            return SafetyDecision(allowed=False, reason=str(exc), audit_event=event)
        except Exception as exc:  # noqa: BLE001 — fail-closed: unexpected errors → deny
            reason = f"Unexpected error during target check: {exc!r}"
            event = self._audit.log_event(
                "safety.error.target",
                {"target": target, "reason": reason},
            )
            log.error("safety.error.target", target=target, exc=repr(exc))
            return SafetyDecision(allowed=False, reason=reason, audit_event=event)

        event = self._audit.log_event("safety.allow.target", {"target": target})
        log.debug("safety.allow.target", target=target)
        return SafetyDecision(allowed=True, reason="Target authorized.", audit_event=event)

    def check_command(self, command: str, target: str) -> SafetyDecision:
        """Check a command-target pair against all safety controls.

        Checks are applied in this order so the most restrictive / cheapest
        check runs first:

        1. **Scope** — is the target authorized?
        2. **Blocklist** — does the command match a forbidden pattern?
        3. **Rate limit** — is this request within the configured RPS budget?

        Args:
            command: Shell command string to validate (not executed here).
            target: Host the command is intended to run against.

        Returns:
            :class:`SafetyDecision` — never raises; always returns a decision.
        """
        try:
            self._scope.assert_in_scope(target)
            self._blocklist.check(command)
            self._ratelimiter.consume(target)
        except SafetyViolationError as exc:
            event = self._audit.log_event(
                "safety.deny.command",
                {
                    "command": command,
                    "target": target,
                    "reason": str(exc),
                    "violation": type(exc).__name__,
                },
            )
            log.warning(
                "safety.deny.command",
                command=command,
                target=target,
                reason=str(exc),
            )
            return SafetyDecision(allowed=False, reason=str(exc), audit_event=event)
        except Exception as exc:  # noqa: BLE001 — fail-closed: unexpected errors → deny
            reason = f"Unexpected error during command check: {exc!r}"
            event = self._audit.log_event(
                "safety.error.command",
                {"command": command, "target": target, "reason": reason},
            )
            log.error("safety.error.command", command=command, target=target, exc=repr(exc))
            return SafetyDecision(allowed=False, reason=reason, audit_event=event)

        event = self._audit.log_event(
            "safety.allow.command", {"command": command, "target": target}
        )
        log.debug("safety.allow.command", command=command, target=target)
        return SafetyDecision(allowed=True, reason="Command authorized.", audit_event=event)
