"""SQLite-backed memory store for sessions, findings, and tool outputs.

All methods are synchronous — SQLite does not have native async support.
Call from async contexts via :func:`asyncio.to_thread` if needed.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from huntersec.core.state import Finding, ToolOutput

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    objective   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_outputs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    step_id     TEXT NOT NULL,
    tool_name   TEXT NOT NULL,
    stdout      TEXT NOT NULL DEFAULT '',
    stderr      TEXT NOT NULL DEFAULT '',
    exit_code   INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_snippets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT,
    content     TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_session   ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_tool_outputs_session ON tool_outputs(session_id);
"""


class MemoryStore:
    """Persistent store backed by SQLite.

    Args:
        db_path: Path to the SQLite database file, or ``":memory:"`` for an
            in-memory database (used in tests).

    Example:
        >>> from huntersec.memory.store import MemoryStore
        >>> store = MemoryStore(":memory:")
        >>> row_id = store.save_finding("s1", {
        ...     "category": "port", "severity": "info",
        ...     "title": "Open 80", "detail": "", "evidence": ""
        ... })
        >>> row_id >= 1
        True
    """

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ── Sessions ───────────────────────────────────────────────────────────────

    def save_session(self, session_id: str, target: str, objective: str) -> None:
        """Record a new session.

        Args:
            session_id: UUID for this session.
            target: Primary target host/IP.
            objective: Assessment objective string.
        """
        now = datetime.now(UTC).isoformat()
        self._conn.execute(
            "INSERT OR IGNORE INTO sessions(id, target, objective, created_at) VALUES(?,?,?,?)",
            (session_id, target, objective, now),
        )
        self._conn.commit()

    # ── Findings ───────────────────────────────────────────────────────────────

    def save_finding(self, session_id: str, finding: Finding) -> int:
        """Persist a single finding.

        Args:
            session_id: Session this finding belongs to.
            finding: Structured finding dict.

        Returns:
            Auto-incremented row ID of the inserted finding.
        """
        now = datetime.now(UTC).isoformat()
        cur = self._conn.execute(
            "INSERT INTO findings"
            "(session_id, category, severity, title, detail, evidence, created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                session_id,
                finding["category"],
                finding["severity"],
                finding["title"],
                finding.get("detail", ""),
                finding.get("evidence", ""),
                now,
            ),
        )
        self._conn.commit()
        return cur.lastrowid or 0

    def save_tool_output(self, session_id: str, output: ToolOutput) -> int:
        """Persist a single tool execution output.

        Args:
            session_id: Session this output belongs to.
            output: Structured tool output dict.

        Returns:
            Auto-incremented row ID.
        """
        cur = self._conn.execute(
            """INSERT INTO tool_outputs
               (session_id, step_id, tool_name, stdout, stderr, exit_code, duration_ms, timestamp)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                session_id,
                output["step_id"],
                output["tool_name"],
                output["stdout"],
                output["stderr"],
                output["exit_code"],
                output["duration_ms"],
                output["timestamp"],
            ),
        )
        self._conn.commit()
        return cur.lastrowid or 0

    def get_session_findings(self, session_id: str) -> list[Finding]:
        """Return all findings for a session, ordered by insertion.

        Args:
            session_id: Session to query.

        Returns:
            List of :class:`~huntersec.core.state.Finding` dicts.
        """
        rows = self._conn.execute(
            "SELECT category, severity, title, detail, evidence FROM findings "
            "WHERE session_id=? ORDER BY id",
            (session_id,),
        ).fetchall()
        return [
            Finding(
                category=r["category"],
                severity=r["severity"],
                title=r["title"],
                detail=r["detail"],
                evidence=r["evidence"],
            )
            for r in rows
        ]

    def search_findings(self, query: str, limit: int = 10) -> list[Finding]:
        """Full-text LIKE search across findings.

        Args:
            query: Search string (matched against title, detail, evidence).
            limit: Maximum number of results to return.

        Returns:
            Matching findings ordered by most recent first.
        """
        pattern = f"%{query}%"
        rows = self._conn.execute(
            """SELECT category, severity, title, detail, evidence FROM findings
               WHERE title LIKE ? OR detail LIKE ? OR evidence LIKE ?
               ORDER BY id DESC LIMIT ?""",
            (pattern, pattern, pattern, limit),
        ).fetchall()
        return [
            Finding(
                category=r["category"],
                severity=r["severity"],
                title=r["title"],
                detail=r["detail"],
                evidence=r["evidence"],
            )
            for r in rows
        ]

    # ── Knowledge snippets ─────────────────────────────────────────────────────

    def save_snippet(self, content: str, source: str = "", session_id: str | None = None) -> int:
        """Save a free-form knowledge snippet.

        Args:
            content: Text content to store.
            source: Origin of the snippet (e.g. ``"hacktricks"``, ``"gtfobins"``).
            session_id: Optional session association.

        Returns:
            Auto-incremented row ID.
        """
        now = datetime.now(UTC).isoformat()
        cur = self._conn.execute(
            "INSERT INTO knowledge_snippets"
            "(session_id, content, source, created_at) VALUES(?,?,?,?)",
            (session_id, content, source, now),
        )
        self._conn.commit()
        return cur.lastrowid or 0

    def search_snippets(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        """LIKE search across knowledge snippets.

        Args:
            query: Search string.
            limit: Maximum results.

        Returns:
            List of dicts with ``content`` and ``source`` keys.
        """
        pattern = f"%{query}%"
        rows = self._conn.execute(
            "SELECT content, source FROM knowledge_snippets WHERE content LIKE ? LIMIT ?",
            (pattern, limit),
        ).fetchall()
        return [{"content": r["content"], "source": r["source"]} for r in rows]

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()
