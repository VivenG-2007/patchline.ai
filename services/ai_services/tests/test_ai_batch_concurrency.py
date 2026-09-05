import asyncio
import json
import os

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")

import pytest

import app.routers.scanner as scanner


def _file(path: str, content: str) -> dict:
    return {"path": path, "content": content}


@pytest.mark.asyncio
async def test_ai_supplemental_scan_runs_batches_concurrently(monkeypatch):
    # Force one file per batch so N files == N independent AI calls, then
    # prove those calls overlap in wall-clock time rather than running
    # strictly one-after-another.
    monkeypatch.setattr(scanner, "_AI_BATCH_MAX_CHARS", 1)
    monkeypatch.setattr(scanner, "_AI_BATCH_CONCURRENCY", 4)

    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    async def fake_chat(messages, model=None):
        nonlocal in_flight, max_in_flight
        async with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.05)  # simulate network latency
        async with lock:
            in_flight -= 1
        return {"content": "[]"}

    class FakeProvider:
        chat = staticmethod(fake_chat)

    monkeypatch.setattr(scanner, "get_provider", lambda: FakeProvider())
    monkeypatch.setattr(scanner, "_scan_model", lambda settings: "fake-model")

    files = [_file(f"file{i}.py", "x" * 10) for i in range(8)]

    start = asyncio.get_event_loop().time()
    await scanner._ai_supplemental_scan(files, "org/repo")
    elapsed = asyncio.get_event_loop().time() - start

    # 8 batches at 0.05s each: fully sequential would take ~0.4s; with
    # concurrency 4 it should take roughly 2 waves (~0.1s), not 8.
    assert elapsed < 0.3, f"batches do not appear to run concurrently (took {elapsed:.3f}s)"
    assert max_in_flight > 1, "no overlap detected between batch calls"
    assert max_in_flight <= 4, "concurrency cap (_AI_BATCH_CONCURRENCY) was not respected"


@pytest.mark.asyncio
async def test_ai_supplemental_scan_preserves_batch_order_despite_concurrency(monkeypatch):
    # Batches "finish" out of order (later batches resolve faster), but the
    # resulting finding IDs must still follow the original batch order —
    # asyncio.gather preserves input order in its results regardless of
    # completion order.
    monkeypatch.setattr(scanner, "_AI_BATCH_MAX_CHARS", 1)
    monkeypatch.setattr(scanner, "_AI_BATCH_CONCURRENCY", 4)

    async def fake_chat(messages, model=None):
        # Later-numbered files resolve fastest, earlier ones slowest —
        # deliberately inverted from arrival order.
        file_marker = messages[1]["content"]
        idx = int(file_marker.split("file")[1].split(".")[0])
        await asyncio.sleep(0.05 * (5 - idx))
        return {
            "content": json.dumps([{
                "title": f"finding-from-file{idx}",
                "severity": "LOW",
                "file": f"file{idx}.py",
                "line": 1,
                "description": "d",
            }])
        }

    class FakeProvider:
        chat = staticmethod(fake_chat)

    monkeypatch.setattr(scanner, "get_provider", lambda: FakeProvider())
    monkeypatch.setattr(scanner, "_scan_model", lambda settings: "fake-model")

    files = [_file(f"file{i}.py", "x" * 10) for i in range(5)]
    findings = await scanner._ai_supplemental_scan(files, "org/repo")

    assert [f.title for f in findings] == [f"finding-from-file{i}" for i in range(5)]
    assert [f.id for f in findings] == [f"AI-{i+1:03d}" for i in range(5)]
