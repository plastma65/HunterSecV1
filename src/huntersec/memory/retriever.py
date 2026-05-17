"""Knowledge retriever — wraps MemoryStore with optional semantic search.

sentence-transformers is a heavy optional dependency.  When not installed,
the retriever silently falls back to LIKE-based text search without crashing.
"""

from __future__ import annotations

import structlog

from huntersec.core.state import Finding
from huntersec.memory.store import MemoryStore

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

try:
    from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]

    _ST_AVAILABLE = True
except ImportError:
    _ST_AVAILABLE = False


class KnowledgeRetriever:
    """Retrieve findings and knowledge snippets relevant to a query.

    Uses semantic similarity search when sentence-transformers is installed;
    falls back to SQL LIKE search otherwise.

    Args:
        store: Underlying :class:`~huntersec.memory.store.MemoryStore`.
        embedding_model: sentence-transformers model name.  Ignored when
            the library is not installed.

    Example:
        >>> from huntersec.memory.store import MemoryStore
        >>> store = MemoryStore(":memory:")
        >>> retriever = KnowledgeRetriever(store)
        >>> results = retriever.retrieve("open port 80")
        >>> isinstance(results, list)
        True
    """

    def __init__(
        self,
        store: MemoryStore,
        embedding_model: str = "all-MiniLM-L6-v2",
    ) -> None:
        self._store = store
        self._model: SentenceTransformer | None = None
        if _ST_AVAILABLE:
            try:
                self._model = SentenceTransformer(embedding_model)
                log.debug("retriever.semantic_search.enabled", model=embedding_model)
            except Exception as exc:  # noqa: BLE001
                log.warning("retriever.semantic_search.disabled", reason=str(exc))

    def retrieve(
        self,
        query: str,
        session_id: str | None = None,
        limit: int = 10,
    ) -> list[Finding]:
        """Retrieve findings relevant to the query.

        Falls back to SQL LIKE search when semantic search is unavailable.

        Args:
            query: Natural language or keyword search string.
            session_id: If provided, restrict results to this session.
            limit: Maximum number of results.

        Returns:
            List of :class:`~huntersec.core.state.Finding` dicts.
        """
        if session_id is not None:
            session_findings = self._store.get_session_findings(session_id)
            if not self._model:
                return session_findings[:limit]
            return self._semantic_filter(query, session_findings, limit)

        # Global search across all sessions
        return self._store.search_findings(query, limit=limit)

    def _semantic_filter(self, query: str, findings: list[Finding], limit: int) -> list[Finding]:
        """Rank findings by cosine similarity to query embedding.

        Args:
            query: Search query.
            findings: Candidate findings to rank.
            limit: Maximum results after ranking.

        Returns:
            Top-``limit`` findings by semantic similarity.
        """
        if not findings or self._model is None:
            return findings[:limit]
        try:
            import numpy as np  # type: ignore[import-untyped]  # noqa: PLC0415

            texts = [f"{f['title']} {f['detail']}" for f in findings]
            q_emb = self._model.encode(query, convert_to_numpy=True)
            f_embs = self._model.encode(texts, convert_to_numpy=True)
            scores: list[float] = [
                float(np.dot(q_emb, fe) / (np.linalg.norm(q_emb) * np.linalg.norm(fe) + 1e-9))
                for fe in f_embs
            ]
            ranked = sorted(zip(scores, findings, strict=False), key=lambda x: x[0], reverse=True)
            return [f for _, f in ranked[:limit]]
        except Exception as exc:  # noqa: BLE001
            log.warning("retriever.semantic_filter.failed", reason=str(exc))
            return findings[:limit]
