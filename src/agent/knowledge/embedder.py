"""Embedding client for the ChromaDB knowledge store.

The default backend is a LOCAL Ollama embedding model (``nomic-embed-text``), so
the container boots and runs with no cloud dependency and nothing leaving the
host — the right default when auditing a partner's own network. Voyage AI
(``voyage-4-lite``, 1024-dim) stays available as an opt-in cloud backend.

Select the backend via environment variables:

  LANCE_EMBEDDINGS      ``ollama`` (default, local) | ``voyage`` (cloud, opt-in)
  LANCE_EMBED_MODEL     Ollama embedding model (default: ``nomic-embed-text``)
  LANCE_EMBED_BASE_URL  OpenAI-compatible endpoint; defaults to
                        ``LANCE_MOE_BASE_URL`` then ``http://localhost:11434/v1``
  LANCE_EMBED_API_KEY   Placeholder key for the local endpoint (default: ``ollama``)
  VOYAGE_API_KEY        Required only when ``LANCE_EMBEDDINGS=voyage``

NOTE: the vector dimension depends on the backend (``nomic-embed-text`` = 768,
``voyage-4-lite`` = 1024). A knowledge store built with one backend cannot be
reused with the other — pick one backend per deployment.
"""

from __future__ import annotations

import os

VOYAGE_EMBEDDING_MODEL = "voyage-4-lite"
DEFAULT_OLLAMA_EMBED_MODEL = "nomic-embed-text"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"

_voyage_client = None
_ollama_client = None


def _backend() -> str:
    """Resolve the active embedding backend (defaults to local Ollama)."""
    return os.environ.get("LANCE_EMBEDDINGS", "ollama").strip().lower()


def _get_voyage_client():
    """Lazy-init the Voyage AI client (opt-in cloud backend)."""
    import voyageai  # lazy import — avoids a hard dependency on the local path

    global _voyage_client
    if _voyage_client is None:
        api_key = os.environ.get("VOYAGE_API_KEY")
        if not api_key:
            raise RuntimeError(
                "LANCE_EMBEDDINGS=voyage but VOYAGE_API_KEY is not set. "
                "Get one at https://dash.voyageai.com/, or use the default local "
                "backend (LANCE_EMBEDDINGS=ollama)."
            )
        _voyage_client = voyageai.Client(api_key=api_key)
    return _voyage_client


def _embed_voyage(texts: list[str]) -> list[list[float]]:
    client = _get_voyage_client()
    result = client.embed(texts, model=VOYAGE_EMBEDDING_MODEL)
    return result.embeddings


def _embed_base_url() -> str:
    """Resolve the local embedding endpoint, reusing the LLM endpoint by default."""
    url = (
        os.environ.get("LANCE_EMBED_BASE_URL")
        or os.environ.get("LANCE_MOE_BASE_URL")
        or DEFAULT_OLLAMA_BASE_URL
    )
    return url.rstrip("/")


def _get_ollama_client():
    """Lazy-init an OpenAI-compatible client pointed at the local Ollama."""
    import openai  # lazy import — keeps module import cheap and backend-agnostic

    global _ollama_client
    if _ollama_client is None:
        _ollama_client = openai.OpenAI(
            base_url=_embed_base_url(),
            # Ollama ignores the key but the OpenAI client requires a non-empty one.
            api_key=os.environ.get("LANCE_EMBED_API_KEY", "ollama"),
        )
    return _ollama_client


def _embed_ollama(texts: list[str]) -> list[list[float]]:
    client = _get_ollama_client()
    model = os.environ.get("LANCE_EMBED_MODEL", DEFAULT_OLLAMA_EMBED_MODEL)
    try:
        resp = client.embeddings.create(model=model, input=texts)
    except Exception as exc:  # noqa: BLE001 — surface a deployment-friendly hint
        raise RuntimeError(
            f"Local embedding call to {_embed_base_url()} failed for model "
            f"'{model}': {exc}. Check LANCE_EMBED_BASE_URL and run "
            f"`ollama pull {model}` on the Ollama host."
        ) from exc
    # The OpenAI embeddings contract does not guarantee data[] ordering; sort by
    # index so vectors stay paired with their input documents positionally.
    return [item.embedding for item in sorted(resp.data, key=lambda d: d.index)]


def embed(texts: list[str]) -> list[list[float]]:
    """Embed a list of texts with the configured backend.

    Returns one float vector per input text.
    """
    if not texts:
        return []
    if _backend() == "voyage":
        return _embed_voyage(texts)
    return _embed_ollama(texts)


def reset_clients() -> None:
    """Drop cached backend clients (useful for tests that change the env)."""
    global _voyage_client, _ollama_client
    _voyage_client = None
    _ollama_client = None
