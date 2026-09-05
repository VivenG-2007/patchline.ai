"""
Shared httpx.AsyncClient for outbound calls to the GitHub API and
raw.githubusercontent.com.

Previously every GitHub call in routers/scanner.py opened its own
`async with httpx.AsyncClient(...)` — a fresh TCP connection plus a fresh
TLS handshake per call, even under concurrent fan-out (a repo scan fetches
up to _FETCH_CONCURRENCY files at once, each paying that setup cost
separately instead of reusing a small pool of keep-alive connections to the
same two hosts). One process-lifetime client with connection pooling turns
that into a handful of real handshakes, reused across every request —
same pattern as es_client.py/redis_client.py in this package.
"""

from __future__ import annotations

from typing import Optional

import httpx

_client: Optional[httpx.AsyncClient] = None


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
            timeout=20,  # per-call timeout is still passed explicitly at each call site
        )
    return _client


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
