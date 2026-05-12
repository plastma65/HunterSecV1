"""Unit tests for huntersec.memory.store.MemoryStore."""

from __future__ import annotations

import pytest

from huntersec.core.state import Finding, ToolOutput
from huntersec.memory.store import MemoryStore


def _make_finding(title: str = "Test Finding", severity: str = "info") -> Finding:
    return Finding(
        category="port",
        severity=severity,
        title=title,
        detail=f"Detail for {title}",
        evidence=f"Evidence: {title}",
    )


def _make_tool_output(tool: str = "nmap", step_id: str = "1") -> ToolOutput:
    return ToolOutput(
        step_id=step_id,
        tool_name=tool,
        stdout=f"{tool} output",
        stderr="",
        exit_code=0,
        duration_ms=100,
        timestamp="2026-05-12T00:00:00",
    )


@pytest.fixture
def store() -> MemoryStore:
    """In-memory SQLite store, isolated per test."""
    return MemoryStore(":memory:")


# ── save_finding ───────────────────────────────────────────────────────────────


def test_save_finding_returns_positive_row_id(store: MemoryStore) -> None:
    row_id = store.save_finding("session-1", _make_finding())
    assert row_id >= 1


def test_save_finding_increments_row_id(store: MemoryStore) -> None:
    id1 = store.save_finding("s1", _make_finding("A"))
    id2 = store.save_finding("s1", _make_finding("B"))
    assert id2 > id1


# ── get_session_findings ───────────────────────────────────────────────────────


def test_get_session_findings_empty_for_unknown_session(store: MemoryStore) -> None:
    findings = store.get_session_findings("nonexistent")
    assert findings == []


def test_get_session_findings_returns_saved_findings(store: MemoryStore) -> None:
    store.save_finding("s1", _make_finding("Port 80"))
    store.save_finding("s1", _make_finding("Port 22"))
    findings = store.get_session_findings("s1")
    assert len(findings) == 2


def test_get_session_findings_preserves_all_fields(store: MemoryStore) -> None:
    original = _make_finding("Critical vuln", "critical")
    store.save_finding("s1", original)
    findings = store.get_session_findings("s1")
    assert findings[0]["title"] == "Critical vuln"
    assert findings[0]["severity"] == "critical"
    assert findings[0]["evidence"] == original["evidence"]


# ── session isolation ──────────────────────────────────────────────────────────


def test_findings_isolated_between_sessions(store: MemoryStore) -> None:
    store.save_finding("session-A", _make_finding("A finding"))
    store.save_finding("session-B", _make_finding("B finding"))
    a_findings = store.get_session_findings("session-A")
    b_findings = store.get_session_findings("session-B")
    assert len(a_findings) == 1
    assert len(b_findings) == 1
    assert a_findings[0]["title"] == "A finding"
    assert b_findings[0]["title"] == "B finding"


# ── save_tool_output ───────────────────────────────────────────────────────────


def test_save_tool_output_returns_positive_row_id(store: MemoryStore) -> None:
    row_id = store.save_tool_output("s1", _make_tool_output())
    assert row_id >= 1


def test_save_multiple_tool_outputs(store: MemoryStore) -> None:
    store.save_tool_output("s1", _make_tool_output("nmap", "1"))
    store.save_tool_output("s1", _make_tool_output("httpx", "2"))
    # Verify they are distinct rows
    id1 = store.save_tool_output("s1", _make_tool_output("gobuster", "3"))
    id2 = store.save_tool_output("s1", _make_tool_output("ffuf", "4"))
    assert id2 > id1


# ── search_findings ────────────────────────────────────────────────────────────


def test_search_findings_returns_matching_by_title(store: MemoryStore) -> None:
    store.save_finding("s1", _make_finding("Apache HTTP Server Detected"))
    store.save_finding("s1", _make_finding("SSH Port Open"))
    results = store.search_findings("Apache")
    assert len(results) == 1
    assert "Apache" in results[0]["title"]


def test_search_findings_matches_detail(store: MemoryStore) -> None:
    f = Finding(
        category="web", severity="medium",
        title="Generic Title",
        detail="Contains SQLi vulnerability in parameter",
        evidence="' OR 1=1--",
    )
    store.save_finding("s1", f)
    results = store.search_findings("SQLi")
    assert len(results) == 1


def test_search_findings_matches_evidence(store: MemoryStore) -> None:
    f = Finding(
        category="port", severity="info",
        title="Port Scan",
        detail="",
        evidence="80/tcp open http Apache",
    )
    store.save_finding("s1", f)
    results = store.search_findings("Apache")
    assert len(results) == 1


def test_search_findings_no_match_returns_empty(store: MemoryStore) -> None:
    store.save_finding("s1", _make_finding("Something else"))
    results = store.search_findings("xyznotfound")
    assert results == []


def test_search_findings_respects_limit(store: MemoryStore) -> None:
    for i in range(20):
        store.save_finding("s1", _make_finding(f"Finding {i} target"))
    results = store.search_findings("target", limit=5)
    assert len(results) <= 5


# ── save_session ───────────────────────────────────────────────────────────────


def test_save_session_does_not_raise(store: MemoryStore) -> None:
    store.save_session("sess-1", "192.0.2.1", "recon")


def test_save_session_idempotent(store: MemoryStore) -> None:
    store.save_session("sess-1", "192.0.2.1", "recon")
    store.save_session("sess-1", "192.0.2.1", "recon")  # second call must not raise


# ── knowledge snippets ─────────────────────────────────────────────────────────


def test_save_snippet_returns_positive_id(store: MemoryStore) -> None:
    row_id = store.save_snippet("GTFOBins: curl can be used for file read", source="gtfobins")
    assert row_id >= 1


def test_search_snippets_finds_by_content(store: MemoryStore) -> None:
    store.save_snippet("curl can read /etc/passwd", source="gtfobins")
    store.save_snippet("wget supports POST requests", source="hacktricks")
    results = store.search_snippets("curl")
    assert any("curl" in r["content"] for r in results)


def test_search_snippets_empty_when_no_match(store: MemoryStore) -> None:
    store.save_snippet("nmap SYN scan", source="docs")
    results = store.search_snippets("kerbrute")
    assert results == []
