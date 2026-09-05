"""
Reconciliation sweep for findings stuck in FIX_PROCESSING.

generate_and_verify_fix (see app/routers/scanner.py) marks a finding
FIX_PROCESSING before doing any real work, and always moves it to a terminal
or retryable status afterward — either via the normal success path, or via
_mark_failed in its except block. That covers every *ordinary* failure (a
GitHub API error, an AI provider error, bad JSON, ...).

What it doesn't cover is a hard crash: the process getting killed (OOM,
deploy, infra-level timeout) partway through the request. Nothing runs the
except block in that case, so the finding is left in FIX_PROCESSING
indefinitely — and per state_machine.TRANSITIONS, FIX_PROCESSING only allows
a self-loop plus the normal completion transitions, not a retry from outside,
so a human can't just re-approve it either.

This module provides a periodic sweep: any finding that's been in
FIX_PROCESSING longer than settings.stuck_fix_processing_minutes is treated
as abandoned and moved to FIX_FAILED (a state findingState.js/state_machine.py
both already allow retrying from), same as a normal caught failure would.
"""

from __future__ import annotations

import asyncio
import datetime

from app.config import get_settings
from app.core.db import get_db
from app.core.logging import get_logger

logger = get_logger()

_STUCK_STATUS = "FIX_PROCESSING"
_RECONCILED_STATUS = "FIX_FAILED"


def _is_stale(processing_started_at: str | None, threshold_minutes: int) -> bool:
    if not processing_started_at:
        # No timestamp recorded (e.g. a record written before this field
        # existed) — treat as stale so it isn't stuck forever with no way
        # to age out; a real in-flight request will simply re-set this
        # field the next time it (re-)enters FIX_PROCESSING.
        return True
    try:
        started = datetime.datetime.fromisoformat(processing_started_at.rstrip("Z"))
    except ValueError:
        return True
    age = datetime.datetime.utcnow() - started
    return age > datetime.timedelta(minutes=threshold_minutes)


async def reconcile_stuck_fixes(threshold_minutes: int | None = None) -> int:
    """Find every scan_history document with a fix stuck in FIX_PROCESSING
    past the staleness threshold and move it to FIX_FAILED so it becomes
    retryable again. Returns the number of findings reconciled."""
    settings = get_settings()
    threshold = threshold_minutes if threshold_minutes is not None else settings.stuck_fix_processing_minutes
    db = get_db()

    cursor = db.scan_history.find({"fixes": {"$exists": True}})
    reconciled = 0
    now_iso = datetime.datetime.utcnow().isoformat() + "Z"

    async for scan_doc in cursor:
        fixes = scan_doc.get("fixes") or {}
        scan_id = scan_doc.get("scanId")
        stale_finding_ids = [
            finding_id
            for finding_id, fix in fixes.items()
            if fix.get("status") == _STUCK_STATUS and _is_stale(fix.get("processingStartedAt"), threshold)
        ]
        if not stale_finding_ids or not scan_id:
            continue

        update = {"$set": {}}
        for finding_id in stale_finding_ids:
            update["$set"][f"fixes.{finding_id}.status"] = _RECONCILED_STATUS
            update["$set"][f"fixes.{finding_id}.error"] = (
                f"Reconciled by the stuck-fix sweep: no update for over {threshold} minutes "
                "(the process handling this fix likely crashed before it could record an outcome)."
            )
            update["$set"][f"fixes.{finding_id}.failedAt"] = now_iso
            update["$set"][f"fixes.{finding_id}.reconciled"] = True

        await db.scan_history.update_one({"scanId": scan_id}, update)
        reconciled += len(stale_finding_ids)
        logger.warning(
            "reconciled_stuck_fixes",
            scan_id=scan_id,
            finding_ids=stale_finding_ids,
            threshold_minutes=threshold,
        )

    if reconciled:
        logger.info("reconciliation_sweep_complete", reconciled_count=reconciled)
    return reconciled


async def run_reconciliation_loop(interval_seconds: int | None = None) -> None:
    """Background task: run the sweep on a fixed interval until cancelled.
    Started from app.main's lifespan and cancelled on shutdown."""
    settings = get_settings()
    interval = interval_seconds if interval_seconds is not None else settings.reconciliation_interval_seconds
    while True:
        try:
            await reconcile_stuck_fixes()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - best-effort background loop
            logger.warning("reconciliation_sweep_failed", error=str(exc))
        await asyncio.sleep(interval)
