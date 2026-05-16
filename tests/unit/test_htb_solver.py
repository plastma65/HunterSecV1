"""Unit tests for huntersec.solvers.htb.solver.HTBSolver."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from huntersec.exceptions import OutOfScopeError
from huntersec.sandbox.executor import ExecutionResult
from huntersec.sandbox.mock import MockSandboxExecutor
from huntersec.solvers.htb.solver import FLAG_PATTERN, HTBSolver, extract_flags
from huntersec.tools.registry import default_registry

_TARGET = "192.0.2.1"
_EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def _exec_result(stdout: str) -> ExecutionResult:
    return {"stdout": stdout, "stderr": "", "exit_code": 0, "duration_ms": 5}


def _write_test_scope(tmp_path: Path) -> Path:
    scope = {
        "version": 1,
        "name": "rfc5737-test",
        "networks": ["192.0.2.0/24", "198.51.100.0/24"],
        "hostnames": [],
        "urls": [],
        "out_of_scope": [],
    }
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump(scope), encoding="utf-8")
    return path


# ── Flag-pattern tests ────────────────────────────────────────────────────────


def test_flag_pattern_matches_32_hex_lowercase() -> None:
    flag = "a" * 32
    assert FLAG_PATTERN.search(flag) is not None


def test_flag_pattern_does_not_match_uppercase_hex() -> None:
    assert FLAG_PATTERN.search("A" * 32) is None


def test_flag_pattern_does_not_match_31_or_33_chars() -> None:
    """\\b[a-f0-9]{32}\\b — boundary requires non-word chars at each end."""
    # 31 hex chars between non-word chars → too short, no match
    assert FLAG_PATTERN.search(" " + ("a" * 31) + " ") is None
    # 33 hex chars run → boundaries on the outside but no exact 32-char window
    # fits between two word-boundary positions, so no match
    assert FLAG_PATTERN.search(" " + ("a" * 33) + " ") is None
    # Exactly 32 hex chars between non-word chars → matches
    assert FLAG_PATTERN.search(" " + ("a" * 32) + " ") is not None


def test_extract_flags_filters_empty_md5() -> None:
    text = f"flag: {_EMPTY_MD5}\nother: aaaabbbbccccddddeeeeffff00001111"
    flags = extract_flags(text)
    assert _EMPTY_MD5 not in flags
    assert "aaaabbbbccccddddeeeeffff00001111" in flags


def test_extract_flags_deduplicates() -> None:
    flag = "1234567890abcdef1234567890abcdef"
    flags = extract_flags(f"{flag}\n{flag}\n{flag}")
    assert flags == [flag]


def test_extract_flags_empty_text_returns_empty_list() -> None:
    assert extract_flags("") == []
    assert extract_flags(None or "") == []


# ── Scope validation ──────────────────────────────────────────────────────────


def test_htb_solver_rejects_out_of_scope_target(tmp_path: Path) -> None:
    scope_path = _write_test_scope(tmp_path)
    with pytest.raises(OutOfScopeError):
        HTBSolver(target_ip="8.8.8.8", scope_file=scope_path)


def test_htb_solver_accepts_in_scope_target(
    tmp_path: Path, safety_filter, audit_logger
) -> None:
    """In-scope target → solver constructable via from_components helper."""
    scope_path = _write_test_scope(tmp_path)
    mock = MockSandboxExecutor()
    registry = default_registry(mock)
    solver = HTBSolver.from_components(
        target_ip=_TARGET,
        scope_file=scope_path,
        safety=safety_filter,
        registry=registry,
        audit=audit_logger,
    )
    assert solver is not None


# ── solve() integration ───────────────────────────────────────────────────────


_NMAP_XML_WITH_FLAG = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


async def test_htb_solver_extracts_flag_from_tool_output(
    tmp_path: Path, safety_filter, audit_logger
) -> None:
    """Solver scans every captured tool output for flag-shaped strings."""
    flag = "deadbeefcafebabe0000111122223333"

    # Embed flag in service version string so it lands in summary text dump
    nmap_with_flag = _NMAP_XML_WITH_FLAG.replace(
        'version="8.9"', f'version="8.9 {flag}"'
    )

    mock = MockSandboxExecutor(
        scripted_results=[
            _exec_result(nmap_with_flag),  # nmap
        ],
        default_result=_exec_result(""),  # everything else empty
    )
    scope_path = _write_test_scope(tmp_path)
    registry = default_registry(mock)
    solver = HTBSolver.from_components(
        target_ip=_TARGET,
        scope_file=scope_path,
        safety=safety_filter,
        registry=registry,
        audit=audit_logger,
    )

    result = await solver.solve()

    assert result["user_flag"] == flag
    assert result["status"] in {"partial", "solved"}


async def test_htb_solver_returns_failed_when_no_flags(
    tmp_path: Path, safety_filter, audit_logger
) -> None:
    mock = MockSandboxExecutor(default_result=_exec_result(""))
    scope_path = _write_test_scope(tmp_path)
    registry = default_registry(mock)
    solver = HTBSolver.from_components(
        target_ip=_TARGET,
        scope_file=scope_path,
        safety=safety_filter,
        registry=registry,
        audit=audit_logger,
    )

    result = await solver.solve()
    assert result["status"] == "failed"
    assert result["user_flag"] is None
    assert result["root_flag"] is None


async def test_htb_solver_writes_report_file(
    tmp_path: Path, safety_filter, audit_logger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Solver should produce a markdown report file at data/reports/."""
    monkeypatch.chdir(tmp_path)
    mock = MockSandboxExecutor(default_result=_exec_result(""))
    scope_path = _write_test_scope(tmp_path)
    registry = default_registry(mock)
    solver = HTBSolver.from_components(
        target_ip=_TARGET,
        scope_file=scope_path,
        safety=safety_filter,
        registry=registry,
        audit=audit_logger,
    )

    result = await solver.solve()
    assert result["report_path"] is not None
    assert result["report_path"].exists()
    assert result["report_path"].suffix == ".md"
