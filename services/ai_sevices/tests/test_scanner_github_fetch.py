import os

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")

import httpx
import pytest

from app.core import github_http
from app.routers import scanner


@pytest.fixture(autouse=True)
async def _reset_client():
    await github_http.close()
    yield
    await github_http.close()


@pytest.mark.asyncio
async def test_fetch_github_file_tree_uses_the_shared_client_and_parses_response():
    requested_urls = []

    def handler(request):
        requested_urls.append(str(request.url))
        return httpx.Response(200, json={
            "tree": [
                {"path": "app.py", "type": "blob"},
                {"path": "README.md", "type": "blob"},
                {"path": "src", "type": "tree"},  # directories should be filtered out by callers
            ]
        })

    github_http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    tree = await scanner._fetch_github_file_tree("acme", "widgets", "main", "gh-token")

    assert len(requested_urls) == 1
    assert "acme/widgets/git/trees/main" in requested_urls[0]
    # _fetch_github_file_tree already filters to blob entries itself (the
    # "src" directory entry above is a tree, correctly excluded).
    assert [item["path"] for item in tree] == ["app.py", "README.md"]


@pytest.mark.asyncio
async def test_fetch_file_content_uses_the_shared_client_and_handles_404():
    def handler(request):
        if "missing.py" in str(request.url):
            return httpx.Response(404)
        return httpx.Response(200, text="print('hello')\n")

    github_http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    content = await scanner._fetch_file_content(
        "https://raw.githubusercontent.com/acme/widgets/main/app.py", "gh-token"
    )
    assert content == "print('hello')\n"

    missing = await scanner._fetch_file_content(
        "https://raw.githubusercontent.com/acme/widgets/main/missing.py", "gh-token"
    )
    assert missing == ""


@pytest.mark.asyncio
async def test_collect_repo_files_fetches_concurrently_through_the_shared_client():
    call_count = 0

    def handler(request):
        nonlocal call_count
        call_count += 1
        url = str(request.url)
        if "git/trees" in url:
            return httpx.Response(200, json={
                "tree": [{"path": f"file{i}.py", "type": "blob"} for i in range(5)]
            })
        return httpx.Response(200, text="x = 1\n")

    github_http._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    files, total_scannable = await scanner._collect_repo_files("acme", "widgets", "main", "gh-token")

    assert total_scannable == 5
    assert len(files) == 5
    assert {f["path"] for f in files} == {f"file{i}.py" for i in range(5)}
    # 1 tree call + 5 file fetches, all through the one shared client
    assert call_count == 6
