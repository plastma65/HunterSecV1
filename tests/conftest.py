"""Root-level pytest fixtures shared across all test categories."""

from __future__ import annotations

from pathlib import Path

import pytest

from huntersec.llm.base import CompletionResponse
from huntersec.llm.fake import FakeLLMProvider
from huntersec.safety.audit import AuditLogger
from huntersec.safety.blocklist import BlocklistChecker
from huntersec.safety.filter import SafetyFilter
from huntersec.safety.ratelimit import RateLimiter
from huntersec.safety.scope import ScopeFile, ScopeValidator

# ── Test scope using RFC-5737 documentation ranges (never real targets) ────────
TEST_SCOPE = ScopeFile(
    version=1,
    name="test-scope",
    networks=[
        "192.0.2.0/24",  # TEST-NET-1  (RFC 5737)
        "198.51.100.0/24",  # TEST-NET-2  (RFC 5737)
        "203.0.113.0/24",  # TEST-NET-3  (RFC 5737)
    ],
    hostnames=["target.example.htb", "lab.htb"],
    urls=["http://192.0.2.1:8080/"],
    out_of_scope=["192.0.2.254"],
)

IN_SCOPE_IP = "192.0.2.1"
OUT_OF_SCOPE_IP = "8.8.8.8"  # Google DNS — never a test target
EXPLICITLY_OUT_OF_SCOPE = "192.0.2.254"


# ── Safety fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def scope_validator() -> ScopeValidator:
    """ScopeValidator loaded from the in-memory test scope."""
    return ScopeValidator(TEST_SCOPE)


@pytest.fixture
def audit_logger(tmp_path: Path) -> AuditLogger:
    """AuditLogger writing to a per-test temp directory."""
    return AuditLogger(tmp_path / "audit")


@pytest.fixture
def blocklist_checker() -> BlocklistChecker:
    """BlocklistChecker with default baked-in rules only."""
    return BlocklistChecker()


@pytest.fixture
def rate_limiter() -> RateLimiter:
    """RateLimiter with generous limits for non-rate-limit tests."""
    return RateLimiter(global_rps=1000.0, per_target_rps=100.0)


@pytest.fixture
def strict_rate_limiter() -> RateLimiter:
    """RateLimiter with very tight limits for rate-limit-specific tests."""
    return RateLimiter(global_rps=2.0, per_target_rps=1.0)


@pytest.fixture
def safety_filter(
    scope_validator: ScopeValidator,
    blocklist_checker: BlocklistChecker,
    rate_limiter: RateLimiter,
    audit_logger: AuditLogger,
) -> SafetyFilter:
    """Fully composed SafetyFilter with generous rate limits."""
    return SafetyFilter(scope_validator, blocklist_checker, rate_limiter, audit_logger)


# ── LLM fixtures ───────────────────────────────────────────────────────────────

_FAKE_RESPONSE = CompletionResponse(
    content="Test response.",
    input_tokens=10,
    output_tokens=5,
    model="fake-model",
)


@pytest.fixture
def fake_response() -> CompletionResponse:
    """A single scripted CompletionResponse for LLM tests."""
    return _FAKE_RESPONSE.model_copy()


@pytest.fixture
def fake_provider() -> FakeLLMProvider:
    """FakeLLMProvider with an infinite default response."""
    return FakeLLMProvider(default_response=_FAKE_RESPONSE.model_copy())
