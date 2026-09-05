"""
Real, backend-confirmed pipeline-stage checkpoints, written to the SAME Redis
instance main-service's scanStore.js already uses (see docker-compose.yml —
both services point at REDIS_URL=redis://redis:6379).

Why this exists: main-service's worker makes exactly ONE blocking HTTP call
per scan/fix (see workers/scannerWorkers.js) and only writes two states to
scan:record:{scanId} — 'PROCESSING' when it starts, and the terminal status
when ai-storage-service's response finally comes back. Everything the
frontend previously showed in between (REPO_FETCHED, DETERMINISTIC_SCAN,
AI_ANALYSIS, ...) was a client-side setInterval incrementing a counter every
1.8s — it had no connection to what this service was actually doing, and
could show "AI Analysis" while the deterministic scanner was still running,
or sit on a stage number for minutes past when the real step actually
finished (or already jumped to a *later* stage before the earlier one was
even attempted, for a fast/small repo).

This module lets THIS service — the one that actually knows what step it's
on — checkpoint that fact somewhere the frontend can read it via
GET /api/scanner/status/:scanId, without adding a new inbound HTTP endpoint
on main-service, a new service, or a new datastore (PatchLine architecture
rule #1: don't introduce duplicate systems / unnecessary services; reuse
existing Redis infrastructure).

Safety: writing this key is NEVER allowed to affect the scan/fix outcome.
Every call is wrapped so a Redis hiccup here can only mean a slightly stale
progress indicator, never a failed scan or a failed fix. It is also written
to a key SEPARATE from scan:record:{scanId} (main-service's own JSON blob),
so this module can never corrupt or race against scanStore.js's
transitionScan/transitionFix writes — it has no read-modify-write dependency
on that key at all.
"""

from __future__ import annotations

from app.core.logging import get_logger
from app.core.redis_client import get_redis

logger = get_logger()

_TTL_SECONDS = 15 * 60  # generous vs. even the slowest realistic scan/fix; self-expires either way

# Real, backend-confirmed checkpoints — one entry per step this service
# actually executes, in the order it executes them. Kept in sync with
# frontend/app/scanner/page.tsx's STAGE_TO_INDEX — if you add/reorder a
# checkpoint here, update that map too.
SCAN_STAGES = ["REPO_FETCHED", "DETERMINISTIC_SCAN", "AI_ANALYSIS", "RISK_ENGINE"]
FIX_STAGES = ["FIX_GENERATING", "CODEX_VERIFYING", "DETERMINISTIC_VERIFYING", "RISK_RECALCULATING"]


def _key(scan_id: str) -> str:
    return f"scan:stage:{scan_id}"


async def report_stage(scan_id: str, stage: str) -> None:
    """Best-effort checkpoint write. Never raises — a failure here must never
    fail the scan/fix it's reporting progress for."""
    try:
        await get_redis().set(_key(scan_id), stage, ex=_TTL_SECONDS)
    except Exception as exc:  # pragma: no cover - best-effort telemetry only
        logger.warning("scan_progress_report_failed", scan_id=scan_id, stage=stage, error=str(exc))


async def clear_stage(scan_id: str) -> None:
    """Called once a terminal status is reached so a stale in-flight stage
    can never be read back for a scan/fix that has already finished."""
    try:
        await get_redis().delete(_key(scan_id))
    except Exception as exc:  # pragma: no cover - best-effort cleanup only
        logger.warning("scan_progress_clear_failed", scan_id=scan_id, error=str(exc))
