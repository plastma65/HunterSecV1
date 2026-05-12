"""Unit tests for huntersec.safety.audit.AuditLogger."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from huntersec.safety.audit import _GENESIS_HASH, AuditEvent, AuditLogger


def test_audit_logger_creates_log_file(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit")
    logger.log_event("test.event", {"key": "value"})
    assert logger.path.exists()


def test_audit_logger_writes_valid_jsonl(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit")
    logger.log_event("test.event", {"x": 1})

    rows = [json.loads(line) for line in logger.path.read_text().splitlines()]
    assert len(rows) == 1
    row = rows[0]
    assert row["event"] == "test.event"
    assert row["payload"] == {"x": 1}
    assert row["seq"] == 1
    assert "hash" in row
    assert "prev_hash" in row
    assert "ts" in row
    assert "session_id" in row


def test_audit_logger_increments_seq(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit")
    for _ in range(5):
        logger.log_event("seq.test")

    rows = [json.loads(line) for line in logger.path.read_text().splitlines()]
    seqs = [r["seq"] for r in rows]
    assert seqs == [1, 2, 3, 4, 5]


def test_audit_logger_hash_chain_starts_from_genesis(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit")
    event = logger.log_event("first.event")
    assert event.prev_hash == _GENESIS_HASH


def test_audit_logger_each_row_prev_hash_matches_previous_hash(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit")
    ev1 = logger.log_event("event.1")
    ev2 = logger.log_event("event.2")
    ev3 = logger.log_event("event.3")

    assert ev2.prev_hash == ev1.hash
    assert ev3.prev_hash == ev2.hash


def test_audit_verify_chain_returns_true_for_intact_log(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit")
    for i in range(10):
        logger.log_event(f"event.{i}", {"seq": i})

    assert AuditLogger.verify_chain(logger.path) is True


def test_audit_verify_chain_detects_hash_tampering(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit")
    logger.log_event("real.event", {"value": "legit"})

    content = logger.path.read_text()
    rows = [json.loads(line) for line in content.splitlines()]
    rows[0]["payload"]["value"] = "tampered"
    tampered = "\n".join(json.dumps(r) for r in rows) + "\n"
    logger.path.write_text(tampered)

    assert AuditLogger.verify_chain(logger.path) is False


def test_audit_verify_chain_detects_prev_hash_mismatch(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit")
    logger.log_event("event.1")
    logger.log_event("event.2")

    content = logger.path.read_text()
    rows = [json.loads(line) for line in content.splitlines()]
    rows[1]["prev_hash"] = "blake3:deadbeef"
    tampered = "\n".join(json.dumps(r) for r in rows) + "\n"
    logger.path.write_text(tampered)

    assert AuditLogger.verify_chain(logger.path) is False


def test_audit_logger_empty_payload_is_allowed(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit")
    event = logger.log_event("bare.event")
    assert event.payload == {}


def test_audit_logger_session_id_is_consistent(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit", session_id="test-session-123")
    ev1 = logger.log_event("e1")
    ev2 = logger.log_event("e2")
    assert ev1.session_id == "test-session-123"
    assert ev2.session_id == "test-session-123"


def test_audit_logger_for_session_factory(tmp_path: Path) -> None:
    logger = AuditLogger.for_session(tmp_path / "audit", "my-session")
    assert logger.session_id == "my-session"


def test_audit_logger_thread_safe(tmp_path: Path) -> None:
    """Multiple threads can log concurrently without corrupting the chain."""
    logger = AuditLogger(tmp_path / "audit")
    errors: list[Exception] = []

    def worker(n: int) -> None:
        try:
            for _ in range(10):
                logger.log_event(f"thread.{n}")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread errors: {errors}"
    assert AuditLogger.verify_chain(logger.path) is True


def test_audit_logger_returns_audit_event_model(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit")
    ev = logger.log_event("model.check")
    assert isinstance(ev, AuditEvent)
    assert ev.seq == 1
