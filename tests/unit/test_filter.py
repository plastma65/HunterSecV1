"""Unit tests for huntersec.safety.filter.SafetyFilter."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from huntersec.exceptions import BlocklistedCommandError, OutOfScopeError, RateLimitExceededError
from huntersec.safety.audit import AuditLogger
from huntersec.safety.blocklist import BlocklistChecker
from huntersec.safety.filter import SafetyFilter
from huntersec.safety.ratelimit import RateLimiter
from huntersec.safety.scope import ScopeFile, ScopeValidator

IN_SCOPE = "192.0.2.1"
OUT_OF_SCOPE = "8.8.8.8"
SAFE_CMD = "nmap -sV 192.0.2.1"
EVIL_CMD = "rm -rf /"


def make_filter(
    tmp_path: Path,
    global_rps: float = 1000.0,
    per_target_rps: float = 100.0,
) -> SafetyFilter:
    """Helper: build a SafetyFilter with RFC test-net scope."""
    scope = ScopeValidator(
        ScopeFile(
            networks=["192.0.2.0/24", "198.51.100.0/24"],
            out_of_scope=[],
        )
    )
    blocklist = BlocklistChecker()
    ratelimiter = RateLimiter(global_rps=global_rps, per_target_rps=per_target_rps)
    audit = AuditLogger(tmp_path / "audit")
    return SafetyFilter(scope, blocklist, ratelimiter, audit)


# ── check_target ──────────────────────────────────────────────────────────────


def test_safety_filter_check_target_in_scope_is_allowed(tmp_path: Path) -> None:
    sf = make_filter(tmp_path)
    decision = sf.check_target(IN_SCOPE)
    assert decision["allowed"] is True


def test_safety_filter_check_target_out_of_scope_is_denied(tmp_path: Path) -> None:
    sf = make_filter(tmp_path)
    decision = sf.check_target(OUT_OF_SCOPE)
    assert decision["allowed"] is False
    assert "scope" in decision["reason"].lower() or "not in" in decision["reason"].lower()


def test_safety_filter_check_target_logs_allow_event(tmp_path: Path) -> None:
    sf = make_filter(tmp_path)
    decision = sf.check_target(IN_SCOPE)
    assert decision["audit_event"].event == "safety.allow.target"


def test_safety_filter_check_target_logs_deny_event(tmp_path: Path) -> None:
    sf = make_filter(tmp_path)
    decision = sf.check_target(OUT_OF_SCOPE)
    assert decision["audit_event"].event == "safety.deny.target"


def test_safety_filter_check_target_rate_limited_is_denied(tmp_path: Path) -> None:
    sf = make_filter(tmp_path, per_target_rps=1.0)
    sf.check_target(IN_SCOPE)  # consume the only token
    decision = sf.check_target(IN_SCOPE)
    assert decision["allowed"] is False
    assert "rate" in decision["reason"].lower()


# ── check_command ─────────────────────────────────────────────────────────────


def test_safety_filter_check_command_valid_is_allowed(tmp_path: Path) -> None:
    sf = make_filter(tmp_path)
    decision = sf.check_command(SAFE_CMD, IN_SCOPE)
    assert decision["allowed"] is True


def test_safety_filter_check_command_out_of_scope_target_is_denied(tmp_path: Path) -> None:
    sf = make_filter(tmp_path)
    decision = sf.check_command(SAFE_CMD, OUT_OF_SCOPE)
    assert decision["allowed"] is False


def test_safety_filter_check_command_blocklisted_is_denied(tmp_path: Path) -> None:
    sf = make_filter(tmp_path)
    decision = sf.check_command(EVIL_CMD, IN_SCOPE)
    assert decision["allowed"] is False
    assert decision["audit_event"].event == "safety.deny.command"


def test_safety_filter_check_command_rate_limited_is_denied(tmp_path: Path) -> None:
    sf = make_filter(tmp_path, per_target_rps=1.0)
    sf.check_command(SAFE_CMD, IN_SCOPE)  # consume token
    decision = sf.check_command(SAFE_CMD, IN_SCOPE)
    assert decision["allowed"] is False


def test_safety_filter_check_command_logs_allow_event(tmp_path: Path) -> None:
    sf = make_filter(tmp_path)
    decision = sf.check_command(SAFE_CMD, IN_SCOPE)
    assert decision["audit_event"].event == "safety.allow.command"


def test_safety_filter_check_command_deny_includes_command_in_payload(tmp_path: Path) -> None:
    sf = make_filter(tmp_path)
    decision = sf.check_command(EVIL_CMD, IN_SCOPE)
    assert decision["audit_event"].payload.get("command") == EVIL_CMD


# ── Fail-closed behaviour ─────────────────────────────────────────────────────


def test_safety_filter_check_target_fail_closed_on_scope_exception(tmp_path: Path) -> None:
    """If scope raises an unexpected error, decision must be deny."""
    # spec=ScopeValidator lets MagicMock expose assert_in_scope without
    # pytest's mock-safety guard treating it as a mis-spelled assertion.
    broken_scope = MagicMock(spec=ScopeValidator)
    broken_scope.assert_in_scope.side_effect = RuntimeError("internal scope failure")
    audit = AuditLogger(tmp_path / "audit")
    sf = SafetyFilter(
        scope=broken_scope,
        blocklist=BlocklistChecker(),
        ratelimiter=RateLimiter(100.0, 10.0),
        audit=audit,
    )
    decision = sf.check_target(IN_SCOPE)
    assert decision["allowed"] is False
    assert decision["audit_event"].event == "safety.error.target"


def test_safety_filter_check_command_fail_closed_on_blocklist_exception(
    tmp_path: Path,
) -> None:
    """If blocklist raises an unexpected error, decision must be deny."""
    scope = ScopeValidator(ScopeFile(networks=["192.0.2.0/24"]))
    broken_blocklist = MagicMock()
    broken_blocklist.check.side_effect = RuntimeError("internal blocklist failure")
    audit = AuditLogger(tmp_path / "audit")
    sf = SafetyFilter(
        scope=scope,
        blocklist=broken_blocklist,
        ratelimiter=RateLimiter(100.0, 10.0),
        audit=audit,
    )
    decision = sf.check_command("nmap -sV 192.0.2.1", IN_SCOPE)
    assert decision["allowed"] is False
    assert decision["audit_event"].event == "safety.error.command"


# ── Decision fields ───────────────────────────────────────────────────────────


def test_safety_filter_decision_has_required_keys(tmp_path: Path) -> None:
    sf = make_filter(tmp_path)
    decision = sf.check_command(SAFE_CMD, IN_SCOPE)
    assert "allowed" in decision
    assert "reason" in decision
    assert "audit_event" in decision


def test_safety_filter_denied_decision_has_non_empty_reason(tmp_path: Path) -> None:
    sf = make_filter(tmp_path)
    decision = sf.check_target(OUT_OF_SCOPE)
    assert decision["reason"]  # non-empty string
