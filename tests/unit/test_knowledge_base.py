"""Unit tests for huntersec.memory.knowledge.KnowledgeBase."""

from __future__ import annotations

from pathlib import Path

import yaml

from huntersec.memory.knowledge import KnowledgeBase


def test_kb_seed_gtfobins_loads_entries() -> None:
    kb = KnowledgeBase(":memory:")
    n = kb.seed_gtfobins()
    assert n >= 10  # at least ~20 in seed
    assert kb.count("gtfobins") >= 10


def test_kb_seed_common_vulns_loads_entries() -> None:
    kb = KnowledgeBase(":memory:")
    n = kb.seed_common_vulns()
    assert n >= 3
    assert kb.count("web_vulns") >= 3


def test_kb_search_returns_relevant_results() -> None:
    kb = KnowledgeBase(":memory:")
    kb.seed_gtfobins()
    hits = kb.search("bash")
    assert hits, "expected at least one bash result"
    assert any("bash" in h["title"].lower() or "bash" in h["content"].lower() for h in hits)


def test_kb_search_with_category_filter() -> None:
    kb = KnowledgeBase(":memory:")
    kb.seed_gtfobins()
    kb.seed_common_vulns()

    gtfo_hits = kb.search("shell", category="gtfobins")
    vuln_hits = kb.search("default", category="web_vulns")

    assert all(h["category"] == "gtfobins" for h in gtfo_hits)
    assert all(h["category"] == "web_vulns" for h in vuln_hits)


def test_kb_seed_is_idempotent() -> None:
    kb = KnowledgeBase(":memory:")
    first = kb.seed_gtfobins()
    second = kb.seed_gtfobins()
    assert first > 0
    assert second == 0  # all duplicates rejected by UNIQUE


def test_kb_loads_from_yaml_file(tmp_path: Path) -> None:
    yaml_path = tmp_path / "seed.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "entries": [
                    {
                        "title": "Custom tool — escape",
                        "content": "Some unique payload string XYZ123.",
                        "source": "test",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    kb = KnowledgeBase(":memory:")
    n = kb.seed_gtfobins(yaml_path=yaml_path)
    assert n == 1
    hits = kb.search("XYZ123")
    assert hits
    assert hits[0]["title"] == "Custom tool — escape"


def test_kb_count_with_no_category_returns_total() -> None:
    kb = KnowledgeBase(":memory:")
    kb.seed_gtfobins()
    kb.seed_common_vulns()
    total = kb.count()
    assert total == kb.count("gtfobins") + kb.count("web_vulns")


def test_kb_search_respects_limit() -> None:
    kb = KnowledgeBase(":memory:")
    kb.seed_gtfobins()
    hits = kb.search("shell", limit=2)
    assert len(hits) <= 2
