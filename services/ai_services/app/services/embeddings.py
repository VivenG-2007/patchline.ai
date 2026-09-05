"""
Embedding provider for the RAG memory pipeline (app/core/memory_store.py).

Mirrors the app/services/ai_providers/ pattern (get_provider() -> chat()):
same idea, one level down — get_embedding_provider() -> embed(). Kept as its
own module (not folded into ai_providers/__init__.py's PROVIDERS map) because
an embedding call returns a vector, not a chat completion, so it isn't a
drop-in fit for that dict's `chat(messages, model) -> dict` shape.

Two providers:
  - "mock" (default, zero-dependency): a deterministic hash-based embedding.
    Not semantically meaningful — it will not cluster genuinely similar
    findings together — but it lets retrieve_similar() and the whole
    index -> retrieve -> augment path run and be exercised with no API key,
    the same reason app/services/ai_providers/mock.py exists. Swap
    EMBEDDING_PROVIDER=azure_openai once real credentials are available.
  - "azure_openai": calls the Azure OpenAI embeddings REST API
    (POST {endpoint}/openai/deployments/{deployment}/embeddings) using the
    same AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY as the chat providers,
    against a separate embedding deployment (text-embedding-3-small or
    equivalent) since chat and embedding models are never the same deployment.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import struct
from typing import Optional

import httpx
from fastapi import HTTPException

from app.config import get_settings

MOCK_EMBEDDING_DIMENSIONS = 256


def _mock_embed(text: str) -> list[float]:
    """Deterministic, dependency-free pseudo-embedding. Same input always
    produces the same vector (needed so re-indexing an unchanged finding
    doesn't drift), but different inputs are NOT guaranteed to land near
    each other in the way a real embedding model's output would — this
    exists to make the pipeline runnable, not to make retrieval good."""
    vector: list[float] = []
    counter = 0
    while len(vector) < MOCK_EMBEDDING_DIMENSIONS:
        digest = hashlib.sha256(f"{text}|{counter}".encode("utf-8")).digest()
        # 8 bytes at a time -> unsigned 64-bit ints -> [-1, 1] floats
        for i in range(0, len(digest) - 7, 8):
            (value,) = struct.unpack_from(">Q", digest, i)
            vector.append((value / 0xFFFFFFFFFFFFFFFF) * 2 - 1)
            if len(vector) >= MOCK_EMBEDDING_DIMENSIONS:
                break
        counter += 1
    norm = math.sqrt(sum(v * v for v in vector)) or 1.0
    return [v / norm for v in vector]


async def _azure_openai_embed(text: str) -> list[float]:
    settings = get_settings()
    api_key = settings.azure_openai_api_key or settings.ai_api_key
    deployment = settings.azure_openai_embedding_deployment
    if not settings.azure_openai_endpoint or not api_key or not deployment:
        raise HTTPException(
            status_code=500,
            detail=(
                "AZURE_OPENAI_EMBEDDING_DEPLOYMENT (plus the existing "
                "AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY) must be set to use "
                "EMBEDDING_PROVIDER=azure_openai"
            ),
        )
    # Strip any path suffix someone may have pasted into AZURE_OPENAI_ENDPOINT
    # (e.g. /openai/v1/responses from the Foundry UI) — same defensive stripping
    # as azure_openai.py so both callers are resilient to the same copy-paste mistake.
    base = settings.azure_openai_endpoint.rstrip("/")
    for suffix in (
        "/openai/v1/responses",
        "/openai/v1",
        "/openai/deployments",
    ):
        if base.endswith(suffix):
            base = base[: -len(suffix)].rstrip("/")
            break
    api_version = settings.azure_openai_api_version or "2024-12-01-preview"
    # Standard Azure OpenAI Embeddings API (different from the Foundry Responses API
    # used by chat — embeddings use the classic deployments path + api-key header,
    # not /openai/v1/responses + Bearer).
    url = f"{base}/openai/deployments/{deployment}/embeddings?api-version={api_version}"

    # A single embedding call is invoked on every fix-generation attempt
    # (memory_store.retrieve_similar, called from _generate_fix on every
    # remediation attempt), so a transient network blip or a momentary 429
    # here shouldn't silently drop RAG for that attempt when a short retry
    # would have succeeded — memory_store already degrades to [] on any
    # exception, but that means "no prior art at all" for that fix, which is
    # a real quality regression worth one quick retry to avoid.
    max_attempts = 3
    backoff_seconds = 0.4
    last_exc: Optional[Exception] = None
    async with httpx.AsyncClient(timeout=30.0) as client:
        for attempt in range(1, max_attempts + 1):
            try:
                resp = await client.post(
                    url,
                    headers={"api-key": api_key, "Content-Type": "application/json"},
                    json={"input": text},
                )
                resp.raise_for_status()
                data = resp.json()
                return data["data"][0]["embedding"]
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError) as exc:
                last_exc = exc
                is_retryable = isinstance(exc, (httpx.TimeoutException, httpx.TransportError)) or (
                    isinstance(exc, httpx.HTTPStatusError)
                    and (exc.response.status_code == 429 or exc.response.status_code >= 500)
                )
                if not is_retryable or attempt == max_attempts:
                    raise
                wait = backoff_seconds * (2 ** (attempt - 1))
                if isinstance(exc, httpx.HTTPStatusError):
                    retry_after = exc.response.headers.get("retry-after")
                    if retry_after:
                        try:
                            wait = min(max(wait, float(retry_after)), 5.0)
                        except ValueError:
                            pass
                await asyncio.sleep(wait)
    # Unreachable in practice (the loop always returns or raises), but keeps
    # the type checker honest and gives a clear error if it ever is.
    raise last_exc or RuntimeError("azure_openai_embed failed with no exception captured")



async def embed(text: str) -> list[float]:
    """Returns an embedding vector for `text`. Provider selected by
    EMBEDDING_PROVIDER (defaults to "mock" — see module docstring)."""
    settings = get_settings()
    provider = settings.embedding_provider
    if provider == "azure_openai":
        return await _azure_openai_embed(text)
    if provider == "mock":
        return _mock_embed(text)
    raise ValueError(f"Unknown EMBEDDING_PROVIDER '{provider}'. Supported: mock, azure_openai")


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
