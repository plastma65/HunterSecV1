"""Append-only JSONL audit log with hash-chain (tamper-evident).

Every security-relevant event MUST go through :class:`AuditLogger.log_event`.
The log is intentionally append-only; rotation happens daily.

Format (one JSON object per line):

.. code-block:: json

    {"ts": "2026-05-11T10:00:00Z",
     "session_id": "uuid",
     "seq": 42,
     "event": "tool.exec",
     "payload": {...},
     "prev_hash": "blake3:...",
     "hash": "blake3:..."}

The ``hash`` field is BLAKE3 of ``(prev_hash || canonical_json(rest))``.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

import blake3
from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    """One event row in the audit log."""

    ts: str
    session_id: str
    seq: int = Field(ge=0)
    event: str
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    hash: str


_GENESIS_HASH = "blake3:0" * 8  # placeholder for chain root


def _canonical_json(obj: Any) -> bytes:
    """Deterministic JSON for hashing — sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _hash(prev_hash: str, payload: dict[str, Any]) -> str:
    h = blake3.blake3()
    h.update(prev_hash.encode())
    h.update(_canonical_json(payload))
    return f"blake3:{h.hexdigest()}"


class AuditLogger:
    """Thread-safe JSONL audit writer with hash chain.

    Args:
        log_dir: Directory to write JSONL files into. Created if missing.
        session_id: UUID for this session; auto-generated if omitted.
    """

    def __init__(self, log_dir: Path, session_id: str | None = None) -> None:
        self._dir = log_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._session_id = session_id or str(uuid.uuid4())
        self._seq = 0
        self._prev_hash = _GENESIS_HASH
        self._lock = threading.Lock()
        date = datetime.now(UTC).strftime("%Y-%m-%d")
        self._path = self._dir / f"{date}_{self._session_id}.jsonl"

    @classmethod
    def for_session(cls, log_dir: Path, session_id: str) -> Self:
        """Create a logger bound to a specific session ID."""
        return cls(log_dir, session_id=session_id)

    @property
    def path(self) -> Path:
        """Absolute path to the active JSONL log file."""
        return self._path

    @property
    def session_id(self) -> str:
        """Session identifier stamped on every emitted event."""
        return self._session_id

    def log_event(self, event: str, payload: dict[str, Any] | None = None) -> AuditEvent:
        """Append a new event, return the persisted row."""
        with self._lock:
            self._seq += 1
            row = {
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "session_id": self._session_id,
                "seq": self._seq,
                "event": event,
                "payload": payload or {},
                "prev_hash": self._prev_hash,
            }
            row["hash"] = _hash(self._prev_hash, row)
            self._prev_hash = row["hash"]
            line = json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
            # Append + fsync for durability
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            return AuditEvent.model_validate(row)

    @staticmethod
    def verify_chain(path: Path) -> bool:
        """Verify hash chain integrity of an existing log file.

        Returns:
            True if every row's ``hash`` matches recomputed value AND chains.
        """
        prev = _GENESIS_HASH
        with path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                row = json.loads(raw)
                stored_hash = row.pop("hash")
                if row["prev_hash"] != prev:
                    return False
                expected = _hash(prev, row)
                if expected != stored_hash:
                    return False
                prev = stored_hash
        return True
