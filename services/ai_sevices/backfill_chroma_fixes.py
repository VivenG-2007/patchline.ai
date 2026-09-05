"""
backfill_chroma_fixes.py
========================
One-off script to repair the finding_memory Chroma Cloud collection after
the `doc`/`scan_doc` NameError bug (fixed in commit c5a64a2) silently
prevented record_fix_outcome() from running for every fix generated between
the bug's introduction and that commit.

What this does
--------------
  1. Scans ALL scan_history documents in MongoDB.
  2. For each document that has a `fixes` map, inspects every finding whose
     fix has a `summary` field set (meaning the AI fix pipeline actually ran).
  3. Checks whether a corresponding Chroma Cloud point already exists for
     that (scanId, findingId) pair.
  4. If the point is MISSING (the memory gap), replays
     memory_store.record_fix_outcome() to backfill it.
  5. If the point already EXISTS but hasFix is False (indexed at scan time
     but the fix outcome was never written), updates it with the fix outcome.
  6. Skips points that already have hasFix=True (already correct — no-op).

Usage
-----
  Run from the services/ai_sevices/ directory with a correctly populated .env:

      python backfill_chroma_fixes.py [--dry-run]

  --dry-run   Print what would be written without touching Chroma Cloud.

Requirements
------------
  Same as the service: all .env variables, especially MONGODB_URI,
  CHROMA_API_KEY, CHROMA_TENANT, CHROMA_DATABASE, and the embedding
  provider config (OPENAI_API_KEY / GEMINI_API_KEY depending on
  EMBEDDING_PROVIDER). RAG_MEMORY_ENABLED must be "true".
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Optional

# Bootstrap .env exactly the same way the FastAPI app does.
from dotenv import load_dotenv
load_dotenv()

from app.config import get_settings
from app.core import chroma_client, db
from app.core.logging import get_logger
from app.core import memory_store

logger = get_logger()

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

async def _chroma_point_exists(collection, doc_id: str) -> Optional[dict]:
    """
    Return the existing metadata dict if the Chroma point exists, else None.
    Runs the synchronous SDK call in a thread so we don't block the event loop.
    """
    result = await asyncio.to_thread(
        collection.get,
        ids=[doc_id],
        include=["metadatas"],
    )
    metadatas = result.get("metadatas") or []
    if metadatas and metadatas[0]:
        return metadatas[0]
    return None


async def backfill(dry_run: bool = False) -> None:
    settings = get_settings()

    if not memory_store.is_enabled():
        print("RAG_MEMORY_ENABLED is not true — nothing to backfill.", flush=True)
        sys.exit(0)

    if not settings.chroma_api_key:
        print("CHROMA_API_KEY is not set — cannot connect to Chroma Cloud.", flush=True)
        sys.exit(1)

    database = db.get_db()
    collection = await chroma_client.get_collection()

    print(f"{'[DRY RUN] ' if dry_run else ''}Scanning MongoDB scan_history for missing Chroma fix outcomes...\n")

    total_scans = 0
    total_fixes_found = 0
    total_skipped_already_ok = 0
    total_backfilled = 0
    total_errors = 0

    cursor = database.scan_history.find({}, {"_id": 0})
    async for scan_doc in cursor:
        total_scans += 1
        scan_id: str = scan_doc.get("scanId", "")
        owner_id: str = scan_doc.get("ownerId", "")
        repo: str = scan_doc.get("repo", "")
        findings: list[dict] = scan_doc.get("findings", []) or []
        fixes: dict = scan_doc.get("fixes", {}) or {}

        # Build a lookup of finding dicts by their ID.
        finding_by_id = {f.get("id"): f for f in findings if f.get("id")}

        for finding_id, fix_data in fixes.items():
            summary: Optional[str] = fix_data.get("summary")
            if not summary:
                # Fix pipeline never completed for this finding — skip.
                continue

            total_fixes_found += 1
            verified: bool = bool(fix_data.get("verified", False))
            method: str = fix_data.get("verificationMethod") or "unknown"
            finding: dict = finding_by_id.get(finding_id, {})

            doc_id = memory_store._doc_id(scan_id, finding_id)

            try:
                existing = await _chroma_point_exists(collection, doc_id)
            except Exception as exc:
                logger.warning("backfill_chroma_check_failed", doc_id=doc_id, error=str(exc))
                total_errors += 1
                continue

            if existing and existing.get("hasFix"):
                # Point exists and already has fix outcome recorded — nothing to do.
                total_skipped_already_ok += 1
                continue

            status = "UPDATE (point exists, hasFix=False)" if existing else "INSERT (point missing)"
            print(
                f"  [{status}] scanId={scan_id} findingId={finding_id} "
                f"verified={verified} method={method}",
                flush=True,
            )

            if not dry_run:
                try:
                    await memory_store.record_fix_outcome(
                        scan_id=scan_id,
                        finding_id=finding_id,
                        summary=summary,
                        verified=verified,
                        method=method,
                        finding=finding if finding else None,
                        owner_id=owner_id if owner_id else None,
                        repo=repo if repo else None,
                    )
                    total_backfilled += 1
                except Exception as exc:
                    logger.warning("backfill_record_fix_failed", doc_id=doc_id, error=str(exc))
                    total_errors += 1
            else:
                total_backfilled += 1  # Count as would-backfill in dry-run mode.

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Backfill complete.")
    print(f"  Scans scanned   : {total_scans}")
    print(f"  Fixes found     : {total_fixes_found}")
    print(f"  Already correct : {total_skipped_already_ok}")
    print(f"  {'Would backfill' if dry_run else 'Backfilled'} : {total_backfilled}")
    print(f"  Errors          : {total_errors}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill missing Chroma fix outcomes from MongoDB scan_history.")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be written without touching Chroma Cloud.")
    args = parser.parse_args()
    asyncio.run(backfill(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
