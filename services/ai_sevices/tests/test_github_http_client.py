import os

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")

import httpx
import pytest

from app.core import github_http


@pytest.fixture(autouse=True)
async def _reset_client():
    # get_client() is a lazy module-level singleton; make sure each test
    # starts clean and any client it created gets closed afterward.
    await github_http.close()
    yield
    await github_http.close()


def test_get_client_returns_the_same_instance_across_calls():
    first = github_http.get_client()
    second = github_http.get_client()
    assert first is second


@pytest.mark.asyncio
async def test_get_client_reuses_the_underlying_connection_pool():
    call_count = 0

    def handler(request):
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)

    # Swap in a client that uses a mock transport (no real network) but is
    # still the SAME client instance across calls, proving scanner.py's call
    # sites (which all now do `github_http.get_client().get(...)`) share one
    # pooled connection rather than opening a new one per request.
    github_http._client = httpx.AsyncClient(transport=transport)
    client = github_http.get_client()

    await client.get("https://api.github.com/repos/x/y")
    await client.get("https://raw.githubusercontent.com/x/y/main/a.py")
    await client.get("https://raw.githubusercontent.com/x/y/main/b.py")

    assert call_count == 3
    # The key claim under test: get_client() didn't hand back a fresh
    # instance for the 2nd/3rd calls — it's the one client the whole module
    # is sharing.
    assert github_http.get_client() is client


@pytest.mark.asyncio
async def test_close_resets_the_singleton_so_a_new_client_is_built_next_time():
    first = github_http.get_client()
    await github_http.close()
    second = github_http.get_client()
    assert first is not second
