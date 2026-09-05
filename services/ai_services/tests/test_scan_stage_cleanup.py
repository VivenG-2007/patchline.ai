# Regression test for run_scan's stage-cleanup guarantee.
#
# scan_progress.report_stage() checkpoints real pipeline progress to Redis
# (scan:stage:{scanId}) so main-service's status endpoint can show it. Before
# this fix, the ONLY place that cleared it was a single explicit
# `await scan_progress.clear_stage(scan_id)` on the success path, right
# before building the response. Any exception raised anywhere in the
# pipeline above that line (GitHub API failure not already caught, a bad
# AI response, a Mongo/blob error that somehow wasn't swallowed, ...) would
# skip that line entirely and leave a stale in-flight stage sitting in Redis
# until its own 15-minute TTL expired — during which a polling frontend
# would keep showing e.g. "AI Analysis" for a scan that had already failed
# outright.
#
# The fix: run_scan is now a thin wrapper around _run_scan_pipeline, with a
# try/finally that unconditionally calls clear_stage() on every exit path —
# success AND exception. This test verifies both halves of that guarantee:
#   1. A pipeline exception still propagates to the caller (this is NOT
#      swallowed — a failed scan must still surface as a failure).
#   2. clear_stage() is called exactly once regardless, with the right scanId.

import os

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")

import pytest

from app.core.security import CurrentUser
from app.routers import scanner
from app.services import scan_progress


def _payload(**overrides):
    base = {"repoOwner": "acme", "repoName": "widgets", "branch": "main"}
    base.update(overrides)
    return scanner.ScanRequest(**base)


@pytest.mark.asyncio
async def test_clear_stage_runs_even_when_the_pipeline_raises(monkeypatch):
    clear_calls = []

    async def fake_clear_stage(scan_id):
        clear_calls.append(scan_id)

    async def raising_pipeline(payload, user, scan_id):
        raise RuntimeError("simulated pipeline failure mid-scan")

    monkeypatch.setattr(scan_progress, "clear_stage", fake_clear_stage)
    monkeypatch.setattr(scanner, "_run_scan_pipeline", raising_pipeline)

    payload = _payload(scanId="scan-fail-1")
    user = CurrentUser(user_id="u1")

    with pytest.raises(RuntimeError, match="simulated pipeline failure"):
        await scanner.run_scan(payload, user)

    # Cleared exactly once, for the right scan, even though the pipeline blew up.
    assert clear_calls == ["scan-fail-1"]


@pytest.mark.asyncio
async def test_clear_stage_runs_on_the_success_path_too(monkeypatch):
    clear_calls = []

    async def fake_clear_stage(scan_id):
        clear_calls.append(scan_id)

    sentinel_response = object()

    async def fake_pipeline(payload, user, scan_id):
        return sentinel_response

    monkeypatch.setattr(scan_progress, "clear_stage", fake_clear_stage)
    monkeypatch.setattr(scanner, "_run_scan_pipeline", fake_pipeline)

    payload = _payload(scanId="scan-ok-1")
    user = CurrentUser(user_id="u1")

    result = await scanner.run_scan(payload, user)

    assert result is sentinel_response
    assert clear_calls == ["scan-ok-1"]


@pytest.mark.asyncio
async def test_a_generated_scan_id_is_used_consistently_for_pipeline_and_cleanup(monkeypatch):
    """When the caller doesn't supply scanId (a manual 'Scan Now', not a
    BullMQ-worker-supplied one), run_scan generates one — clear_stage must
    be called with that SAME generated id, not None/a different one."""
    seen_scan_ids = {}

    async def fake_clear_stage(scan_id):
        seen_scan_ids["cleared"] = scan_id

    async def fake_pipeline(payload, user, scan_id):
        seen_scan_ids["pipeline"] = scan_id
        return "ok"

    monkeypatch.setattr(scan_progress, "clear_stage", fake_clear_stage)
    monkeypatch.setattr(scanner, "_run_scan_pipeline", fake_pipeline)

    payload = _payload()  # no scanId
    user = CurrentUser(user_id="u1")
    await scanner.run_scan(payload, user)

    assert seen_scan_ids["pipeline"] is not None
    assert seen_scan_ids["cleared"] == seen_scan_ids["pipeline"]
