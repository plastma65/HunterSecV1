"""Safety layer — scope guard, blocklist, audit log, rate limiter.

This module is **load-bearing**: every offensive action MUST pass through
:class:`SafetyFilter` before reaching the sandbox.

Coverage target: 95% line + branch (see CLAUDE.md §3.1).
"""

from __future__ import annotations

from huntersec.safety.audit import AuditEvent, AuditLogger
from huntersec.safety.blocklist import BlocklistChecker
from huntersec.safety.filter import SafetyDecision, SafetyFilter
from huntersec.safety.ratelimit import RateLimiter
from huntersec.safety.scope import ScopeFile, ScopeValidator

__all__ = [
    "AuditEvent",
    "AuditLogger",
    "BlocklistChecker",
    "RateLimiter",
    "SafetyDecision",
    "SafetyFilter",
    "ScopeFile",
    "ScopeValidator",
]
