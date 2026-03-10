"""Embedding client using Voyage AI (voyage-4-lite).

Anthropic recommends Voyage AI for embeddings. voyage-4-lite produces
1024-dim vectors at $0.02/1M tokens with 200M free tokens per account.

Requires VOYAGE_API_KEY in environment (.env).
"""

from __future__ import annotations

import os

import voyageai

EMBEDDING_MODEL = "voyage-4-lite"
EMBEDDING_DIMS = 1024

_client: voyageai.Client | None = None


def _get_client() -> voyageai.Client:
    """Lazy-init the Voyage AI client."""
    global _client
    if _client is None:
        api_key = os.environ.get("VOYAGE_API_KEY")
        if not api_key:
            raise RuntimeError(
                "VOYAGE_API_KEY not set. Get one at https://dash.voyageai.com/"
            )
        _client = voyageai.Client(api_key=api_key)
    return _client


def embed(texts: list[str]) -> list[list[float]]:
    """Embed a list of texts using Voyage AI.

    Returns a list of 1024-dimensional float vectors.
    """
    if not texts:
        return []
    client = _get_client()
    result = client.embed(texts, model=EMBEDDING_MODEL)
    return result.embeddings


def embed_query(text: str) -> list[float]:
    """Embed a single query string. Convenience wrapper."""
    return embed([text])[0]
