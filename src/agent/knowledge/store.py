"""ChromaDB-backed knowledge store with cache-then-query pattern.

Collections:
  - cve_knowledge: CVE descriptions from NVD
  - skills: IoT attack methodology chunks

The store is persistent (data/knowledge.db) and grows over time.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable

import chromadb

from src.agent.knowledge.embedder import embed, EMBEDDING_DIMS

log = logging.getLogger(__name__)

DATA_DIR = Path("data/knowledge.db")

_chroma_client: chromadb.ClientAPI | None = None


def _get_client() -> chromadb.ClientAPI:
    """Lazy-init a persistent ChromaDB client, with EphemeralClient fallback."""
    global _chroma_client
    if _chroma_client is None:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            _chroma_client = chromadb.PersistentClient(path=str(DATA_DIR))
        except Exception as e:
            log.warning("PersistentClient failed (%s), falling back to EphemeralClient", e)
            _chroma_client = chromadb.EphemeralClient()
    return _chroma_client


class _VoyageEmbeddingFunction(chromadb.EmbeddingFunction):
    """ChromaDB embedding function backed by Voyage AI."""

    def __call__(self, input: list[str]) -> list[list[float]]:  # noqa: A002
        return embed(input)


_embedding_fn = _VoyageEmbeddingFunction()


def get_collection(name: str) -> chromadb.Collection:
    """Get or create a named collection with Voyage embeddings."""
    client = _get_client()
    return client.get_or_create_collection(
        name=name,
        embedding_function=_embedding_fn,
        metadata={"hnsw:space": "cosine"},
    )


def ingest(
    collection_name: str,
    documents: list[str],
    metadatas: list[dict[str, Any]] | None = None,
    ids: list[str] | None = None,
) -> int:
    """Add documents to a collection. Returns count of documents added."""
    if not documents:
        return 0

    collection = get_collection(collection_name)

    if ids is None:
        existing_count = collection.count()
        ids = [f"{collection_name}_{existing_count + i}" for i in range(len(documents))]

    collection.upsert(
        documents=documents,
        metadatas=metadatas,
        ids=ids,
    )
    log.info("Ingested %d documents into '%s'", len(documents), collection_name)
    return len(documents)


def search(
    collection_name: str,
    query: str,
    top_k: int = 5,
    threshold: float = 0.7,
    where: dict | None = None,
) -> list[dict[str, Any]]:
    """Semantic search in a collection.

    Returns list of {id, document, metadata, distance, similarity} dicts,
    filtered by similarity >= threshold.
    """
    collection = get_collection(collection_name)

    if collection.count() == 0:
        return []

    kwargs: dict[str, Any] = {
        "query_texts": [query],
        "n_results": min(top_k, collection.count()),
    }
    if where:
        kwargs["where"] = where

    results = collection.query(**kwargs)

    hits = []
    for i in range(len(results["ids"][0])):
        distance = results["distances"][0][i]
        similarity = 1.0 - distance

        if similarity < threshold:
            continue

        hits.append({
            "id": results["ids"][0][i],
            "document": results["documents"][0][i],
            "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
            "distance": distance,
            "similarity": round(similarity, 4),
        })

    return hits


def get_or_fetch(
    collection_name: str,
    query: str,
    fetch_fn: Callable[[str], list[dict[str, Any]]],
    top_k: int = 5,
    threshold: float = 0.7,
    id_field: str = "id",
    doc_field: str = "document",
) -> list[dict[str, Any]]:
    """Cache-then-query pattern.

    1. Search ChromaDB for existing results.
    2. If cache miss (no results above threshold), call fetch_fn(query).
    3. Ingest fetched results into ChromaDB for next time.
    4. Return results.
    """
    cached = search(collection_name, query, top_k=top_k, threshold=threshold)
    if cached:
        log.info("Cache hit for '%s' in '%s': %d results", query, collection_name, len(cached))
        return cached

    log.info("Cache miss for '%s' in '%s', fetching live...", query, collection_name)

    try:
        fetched = fetch_fn(query)
    except Exception as e:
        log.error("Fetch failed for '%s': %s", query, e)
        return []

    if not fetched:
        return []

    documents = [item.get(doc_field, str(item)) for item in fetched]
    ids = [item.get(id_field, f"fetched_{i}") for i, item in enumerate(fetched)]
    metadatas = [{k: v for k, v in item.items() if k not in (doc_field,)} for item in fetched]

    ingest(collection_name, documents=documents, ids=ids, metadatas=metadatas)

    # Return the fetched items directly rather than re-searching the whole
    # collection: re-searching with threshold=0.0 would pull in unrelated
    # cached documents from previous queries.
    return [
        {
            "id": item.get(id_field, f"fetched_{i}"),
            "document": item.get(doc_field, str(item)),
            "metadata": {k: v for k, v in item.items() if k not in (doc_field,)},
        }
        for i, item in enumerate(fetched[:top_k])
    ]


def collection_stats(collection_name: str) -> dict[str, Any]:
    """Return stats for a collection."""
    collection = get_collection(collection_name)
    return {
        "name": collection_name,
        "count": collection.count(),
    }


def reset_client() -> None:
    """Reset the ChromaDB client (useful for testing)."""
    global _chroma_client
    _chroma_client = None
